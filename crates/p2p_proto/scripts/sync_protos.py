#!/usr/bin/env python3
import os
import re
import sys
import shutil
import subprocess
import tempfile
import zipfile
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Set
from urllib.request import urlretrieve

REPO_URL = "https://github.com/starknet-io/starknet-p2p-specs"
ZIP_MAIN = "https://github.com/starknet-io/starknet-p2p-specs/archive/refs/heads/main.zip"

log = logging.getLogger("proto-sync")

class RepoFetcherError(Exception): pass

def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    log.debug("RUN %s (cwd=%s)", " ".join(cmd), cwd or os.getcwd())
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)

def try_git_clone(repo_url: str, dest_dir: Path, ref: str | None) -> Path:
    log.info("Attempting shallow git clone...")
    repo_root = dest_dir / "starknet-p2p-specs"
    cp = run(["git", "clone", "--depth", "1", repo_url, str(repo_root)])
    if cp.stdout.strip():
        log.debug(cp.stdout.strip())
    if ref:
        log.info("Checking out ref %s...", ref)
        # fetch the ref explicitly in case it's not in depth-1
        try:
            run(["git", "fetch", "--depth", "1", "origin", ref], cwd=repo_root)
        except subprocess.CalledProcessError:
            # fall back to full fetch for that ref
            log.info("Depth=1 fetch failed, doing a targeted fetch for %s...", ref)
            run(["git", "fetch", "origin", ref], cwd=repo_root)
        run(["git", "checkout", "FETCH_HEAD"], cwd=repo_root)
    log.info("git clone OK -> %s", repo_root)
    return repo_root

def download_and_unzip(url: str, dest_dir: Path) -> Path:
    log.info("Downloading ZIP: %s", url)
    zip_path = dest_dir / "repo.zip"
    urlretrieve(url, zip_path)
    log.info("Extracting ZIP...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest_dir)
    for child in dest_dir.iterdir():
        if child.is_dir() and child.name.startswith("starknet-p2p-specs"):
            log.info("ZIP extracted to: %s", child)
            return child
    raise RepoFetcherError("Could not locate extracted repo root from ZIP")

def fetch_repo(repo_url: str, workdir: Path, ref: str | None) -> Path:
    try:
        return try_git_clone(repo_url, workdir, ref)
    except FileNotFoundError:
        log.warning("'git' not found. Falling back to ZIP download.")
    except subprocess.CalledProcessError as e:
        log.warning("git clone failed. Falling back to ZIP. stderr: %s", (e.stderr or "").strip())

    # ZIP fallback (ref is not supported here; we get the branch state)
    try:
        return download_and_unzip(ZIP_MAIN, workdir)
    except Exception as e_main:
        log.warning("main.zip failed: %s", e_main)
        raise RepoFetcherError(f"Failed to fetch repository via ZIP: {e_main}")

def find_p2p_proto_dir(repo_root: Path) -> Path:
    log.info("Locating 'p2p/proto' in the repository...")
    candidates = list(repo_root.rglob("p2p/proto"))
    for c in candidates:
        if c.is_dir():
            log.info("Using proto source dir: %s", c)
            return c
    raise RepoFetcherError("Could not find 'p2p/proto' directory in the repository")

class ProtoSyncAndFixer:
    def __init__(self, proto_src_dir: str, proto_dir: str = "proto"):
        self.proto_src_dir = Path(proto_src_dir)
        self.proto_dir = Path(proto_dir)
        self.package_map: Dict[str, str] = {}
        self.import_map: Dict[str, List[str]] = {}
        self.type_definitions: Dict[str, Set[str]] = {}
        self.file_packages: Dict[str, str] = {}

    def sync_proto_files(self):
        log.info("Syncing proto files from %s -> %s...", self.proto_src_dir, self.proto_dir)

        if self.proto_dir.exists():
            shutil.rmtree(self.proto_dir)
        self.proto_dir.mkdir(parents=True, exist_ok=True)

        count = 0
        for proto_file in self.proto_src_dir.rglob("*.proto"):
            relative_path = proto_file.relative_to(self.proto_src_dir)
            target_file = self.proto_dir / relative_path
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(proto_file, target_file)
            log.debug("Copied: %s -> %s", proto_file, target_file)
            count += 1

        if count == 0:
            raise RuntimeError(f"No .proto files found under {self.proto_src_dir}")
        log.info("Copied %d .proto files.", count)

    def add_package_declarations(self):
        log.info("Adding/normalizing package declarations...")
        for proto_file in self.proto_dir.rglob("*.proto"):
            self._add_package_to_file(proto_file)

    def _add_package_to_file(self, proto_file: Path):
        relative_path = proto_file.relative_to(self.proto_dir)
        package_parts = relative_path.parent.parts + (relative_path.stem,)
        package_name = "starknet." + ".".join(package_parts)

        with open(proto_file, 'r', encoding='utf-8') as f:
            content = f.read()

        package_match = re.search(r'package\s+([a-zA-Z_][a-zA-Z0-9_.]*);', content)
        if package_match:
            existing = package_match.group(1)
            if existing.startswith('starknet.'):
                package_name = existing
            else:
                content = re.sub(r'package\s+[^;]+;', f'package {package_name};', content)
        else:
            if 'syntax = "proto3";' in content:
                content = content.replace(
                    'syntax = "proto3";',
                    'syntax = "proto3";\n\npackage ' + package_name + ';\n'
                )
            else:
                content = 'syntax = "proto3";\n\npackage ' + package_name + ';\n' + content

        with open(proto_file, 'w', encoding='utf-8') as f:
            f.write(content)

        self.package_map[str(proto_file)] = package_name
        self.file_packages[str(proto_file)] = package_name
        log.debug("Package for %s -> %s", proto_file, package_name)

    def update_imports(self):
        """Update import statements to use correct paths (write only if changed)."""
        log.info("Rewriting import statements...")
        for proto_file in self.proto_dir.rglob("*.proto"):
            with open(proto_file, 'r', encoding='utf-8') as f:
                content = f.read()

            imports = re.findall(r'import\s+"([^"]+)";', content)
            if not imports:
                # nothing to do; leave file untouched (prevents blank lines)
                continue

            updated = content
            for old in imports:
                if old.startswith('p2p/proto/'):
                    new = 'proto/' + old[len('p2p/proto/'):]
                    updated = updated.replace(f'import "{old}";', f'import "{new}";')

            self._write_if_changed(proto_file, content, updated)


    def remove_go_package_options(self):
        log.info("Removing go_package options...")
        for proto_file in self.proto_dir.rglob("*.proto"):
            with open(proto_file, 'r', encoding='utf-8') as f:
                content = f.read()
            lines = content.splitlines()
            filtered = [ln for ln in lines if not ln.strip().startswith('option go_package')]
            if len(filtered) < len(lines):
                with open(proto_file, 'w', encoding='utf-8') as f:
                    f.write("\n".join(filtered))
                log.debug("Removed go_package from %s", proto_file)

    def parse_proto_files(self):
        log.info("Parsing proto files...")
        for proto_file in self.proto_dir.rglob("*.proto"):
            with open(proto_file, 'r', encoding='utf-8') as f:
                content = f.read()

            pkg_m = re.search(r'package\s+([a-zA-Z_][a-zA-Z0-9_.]*);', content)
            if not pkg_m:
                log.warning("No package found in %s", proto_file)
                continue
            pkg = pkg_m.group(1)
            self.package_map[str(proto_file)] = pkg
            self.file_packages[str(proto_file)] = pkg

            imports = re.findall(r'import\s+"([^"]+)";', content)
            self.import_map[str(proto_file)] = imports

            messages = re.findall(r'(?:^|\s)message\s+([A-Za-z_][A-Za-z0-9_]*)', content, re.MULTILINE)
            enums = re.findall(r'enum\s+([A-Za-z_][A-Za-z0-9_]*)', content)
            if pkg not in self.type_definitions:
                self.type_definitions[pkg] = set()
            self.type_definitions[pkg].update(messages)
            self.type_definitions[pkg].update(enums)

    def resolve_import_paths(self):
        log.info("Resolving import types across files...")
        self.resolved_imports: Dict[str, Dict[str, str]] = {}

        for file_path, imports in self.import_map.items():
            self.resolved_imports[file_path] = {}
            for imp in imports:
                if imp.startswith('proto/'):
                    rel = imp[6:]
                    import_file = self.proto_dir / rel
                else:
                    import_file = self.proto_dir / imp

                if import_file.exists():
                    import_pkg = self.file_packages.get(str(import_file))
                    if import_pkg:
                        for t in self.type_definitions.get(import_pkg, set()):
                            self.resolved_imports[file_path][t] = import_pkg
                else:
                    log.warning("Import file not found for %s -> %s", file_path, import_file)

    def fix_type_references(self):
        log.info("Qualifying external type references...")
        for proto_file in self.proto_dir.rglob("*.proto"):
            file_path = str(proto_file)
            with open(proto_file, 'r', encoding='utf-8') as f:
                content = f.read()

            importable = self.resolved_imports.get(file_path, {})
            current_pkg = self.file_packages.get(file_path, "")
            local_types = self.type_definitions.get(current_pkg, set())
            external = {name: pkg for name, pkg in importable.items() if name not in local_types}

            if not external:
                continue

            modified = content
            for type_name, package_name in external.items():
                pattern = rf'(\s){type_name}(\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\d+)'
                opt_pat = rf'(optional\s+){type_name}(\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\d+)'
                rep_pat = rf'(repeated\s+){type_name}(\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*\d+)'
                replacement = rf'\1{package_name}.{type_name}\2'
                opt_repl = rf'\1{package_name}.{type_name}\2'
                rep_repl = rf'\1{package_name}.{type_name}\2'

                modified = re.sub(pattern, replacement, modified)
                modified = re.sub(opt_pat, opt_repl, modified)
                modified = re.sub(rep_pat, rep_repl, modified)

            if modified != content:
                with open(proto_file, 'w', encoding='utf-8') as f:
                    f.write(modified)

    def _write_if_changed(self, path: Path, original: str, updated: str) -> bool:
        """Write file only if content changed. Returns True if written."""
        if updated != original:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(updated)
            return True
        return False

    def format_top_matter(self, text: str) -> str:
        """
        Enforce exactly one blank line between:
        syntax -> package -> imports -> (one blank line) -> rest
        Preserve the order of imports. Leave the rest of the file unchanged,
        except for trimming leading blank lines and ensuring a single trailing newline.
        """
        # Extract pieces
        syntax_re = re.compile(r'^\s*syntax\s*=\s*"(?:proto2|proto3)";\s*', re.MULTILINE)
        package_re = re.compile(r'^\s*package\s+[a-zA-Z_][a-zA-Z0-9_.]*;\s*', re.MULTILINE)
        import_re = re.compile(r'^\s*import\s+"[^"]+";\s*', re.MULTILINE)

        # Find first occurrences
        syntax_m = syntax_re.search(text)
        if not syntax_m:
            # Nothing we can format without syntax; just normalize trailing newline and return.
            return text.rstrip() + "\n"

        package_m = package_re.search(text)
        imports = list(import_re.finditer(text))

        # Build clean header
        syntax_line = syntax_m.group(0).strip()
        package_line = package_m.group(0).strip() if package_m else None
        import_lines = [m.group(0).strip() for m in imports]

        # Remove extracted parts from body
        pieces = []
        last = 0
        # mask out matched regions so we can collect the rest
        spans = [syntax_m.span()]
        if package_m:
            spans.append(package_m.span())
        spans.extend(m.span() for m in imports)
        spans.sort()

        for start, end in spans:
            pieces.append(text[last:start])
            last = end
        pieces.append(text[last:])
        body = "".join(pieces)

        # Trim leading blank lines from body; keep internal spacing intact
        body = re.sub(r'^\s*\n', '', body, count=1)

        # Assemble header with exact spacing
        header_parts = [syntax_line]
        if package_line:
            header_parts.append("")         # blank line after syntax
            header_parts.append(package_line)
        if import_lines:
            if not package_line:
                header_parts.append("")     # blank line after syntax if no package but we have imports
            header_parts.append("")         # blank line before imports
            header_parts.extend(import_lines)

        # One blank line between imports and body (only if there are imports or package)
        if package_line or import_lines:
            header_parts.append("")

        new_text = "\n".join(header_parts).rstrip() + "\n"

        if body.strip():
            # Ensure exactly one blank line between header and body
            body = body.lstrip("\n")              # remove any leading newlines
            new_text += "\n" + body               # always add one newline before body
        else:
            # no body, just ensure single trailing newline
            new_text = new_text.rstrip() + "\n"

        return new_text

    def run_complete_workflow(self):
        self.sync_proto_files()
        self.add_package_declarations()
        self.update_imports()
        self.remove_go_package_options()

        # Format the top matter of all proto files
        for proto_file in self.proto_dir.rglob("*.proto"):
            with open(proto_file, 'r', encoding='utf-8') as f:
                original = f.read()
            formatted = self.format_top_matter(original)
            self._write_if_changed(proto_file, original, formatted)

        self.parse_proto_files()
        self.resolve_import_paths()
        self.fix_type_references()

        log.info("✔️  Workflow completed successfully.")

def main():
    parser = argparse.ArgumentParser(description="Sync and fix protos from a hardcoded repo.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument("--ref", default=None, help="Optional git ref (branch/tag/commit) to checkout.")
    args = parser.parse_args()

    # Configure logging
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(stream=sys.stdout, level=level, format="%(levelname)s: %(message)s", force=True)

    log.info("Source repository: %s", REPO_URL)
    if args.ref:
        log.info("Requested ref: %s", args.ref)

    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            repo_root = fetch_repo(REPO_URL, tmpdir, args.ref)
            proto_src_dir = find_p2p_proto_dir(repo_root)

            fixer = ProtoSyncAndFixer(str(proto_src_dir), proto_dir="proto")
            fixer.run_complete_workflow()
        log.info("Temporary files cleaned up.")
    except RepoFetcherError as e:
        log.error("Repository fetch error: %s", e)
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        log.error("Command failed: %s\nstdout:\n%s\nstderr:\n%s", " ".join(e.cmd), e.stdout, e.stderr)
        sys.exit(3)
    except Exception as e:
        log.exception("Unexpected error: %s", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
