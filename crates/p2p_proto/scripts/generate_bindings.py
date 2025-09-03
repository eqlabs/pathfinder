#!/usr/bin/env python3
"""
Generate lib.rs file to match the actual proto structure
=======================================================

This script analyzes the generated .rs files and creates a lib.rs that properly
reflects the hierarchical structure of the protobuf packages.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Set

def analyze_proto_files(proto_dir: str = "proto") -> Dict[str, List[str]]:
    """Analyze the .proto files directly to understand the structure."""
    proto_path = Path(proto_dir)
    if not proto_path.exists():
        print(f"Error: Proto directory {proto_dir} does not exist")
        return {}

    # Find all .proto files
    proto_files = list(proto_path.rglob("*.proto"))

    # Group by package hierarchy
    package_structure: Dict[str, List[str]] = {}

    for proto_file in proto_files:
        # Read the file to get the package declaration
        with open(proto_file, 'r') as f:
            content = f.read()

        # Extract package name from "package starknet.xxx;"
        package_match = re.search(r'package\s+([^;]+);', content)
        if package_match:
            package_name = package_match.group(1)

            # Split into parts
            parts = package_name.split('.')

            if len(parts) >= 2:
                # First part is always "starknet"
                if parts[0] == "starknet":
                    # Second part is the main module
                    main_module = parts[1]

                    if main_module not in package_structure:
                        package_structure[main_module] = []

                    # Add the full package name
                    package_structure[main_module].append(package_name)

    return package_structure


def generate_module_declaration(package_name: str, is_large_enum: bool = False) -> str:
    """Generate a module declaration for a given package."""
    # Convert package name to module path
    module_path = package_name.replace('starknet.', '').replace('.', '::')

    # Determine if we need the large_enum_variant attribute
    attr = ""
    if is_large_enum:
        attr = "        #[allow(clippy::large_enum_variant)]\n"

    return f"{attr}        pub mod {module_path.split('::')[-1]} {{\n            include!(concat!(env!(\"OUT_DIR\"), \"/{package_name}.rs\"));\n        }}"

def generate_lib_rs_content(package_structure: Dict[str, List[str]]) -> str:
    """Generate the complete lib.rs content."""
    lines = [
        "#[allow(clippy::module_inception)]",
        "pub mod proto {",
    ]

    # Sort main modules for consistent output
    for main_module in sorted(package_structure.keys()):
        packages = package_structure[main_module]

        if len(packages) == 1 and packages[0] == f"starknet.{main_module}":
            # Simple case: starknet.common -> pub mod common
            lines.append("")
            lines.append(f"    pub mod {main_module} {{")
            lines.append(f"        include!(concat!(env!(\"OUT_DIR\"), \"/starknet.{main_module}.rs\"));")
            lines.append("    }")
        else:
            # Complex case: nested modules like starknet.sync.class
            lines.append("")
            lines.append(f"    pub mod {main_module} {{")

            # Sort nested packages for consistent output
            nested_packages = sorted(packages)

            # First, include the main module file if it exists
            main_package = f"starknet.{main_module}"
            if main_package in packages:
                lines.append(f"        include!(concat!(env!(\"OUT_DIR\"), \"/{main_package}.rs\"));")

            # Then add nested modules
            for package in nested_packages:
                if package != main_package:
                    # This is a nested module
                    nested_module = package.replace(f"starknet.{main_module}.", "")

                    # Check if this module might have large enums (common ones)
                    is_large_enum = nested_module in ['header', 'receipt', 'transaction', 'class']

                    lines.append(generate_module_declaration(package, is_large_enum))

            lines.append("    }")

    lines.append("}")
    lines.append("")

    # Add the trait implementations
    lines.extend([
        "// ToProtobuf and TryFromProtobuf traits and implementations",
        "// ... (existing trait code would go here)",
    ])

    return "\n".join(lines)

def update_lib_rs_file(package_structure: Dict[str, List[str]], lib_rs_path: Path):
    """Update only the proto module section in lib.rs while preserving the rest."""
    print(f"📝 Updating proto module section in {lib_rs_path}")

    # Read the existing file
    with open(lib_rs_path, 'r') as f:
        content = f.read()

    # Find the proto module section
    proto_start = content.find("pub mod proto {")
    if proto_start == -1:
        print("❌ Could not find 'pub mod proto {' in lib.rs")
        return False

    # Find the end of the proto module section by counting braces
    # Start after the opening brace
    start_pos = proto_start + len("pub mod proto {")
    brace_count = 1  # We're already inside the proto module
    proto_end = -1

    for i, char in enumerate(content[start_pos:], start_pos):
        if char == '{':
            brace_count += 1
        elif char == '}':
            brace_count -= 1
            if brace_count == 0:
                proto_end = i
                break

    if proto_end == -1:
        print("❌ Could not find end of proto module section")
        return False

    # Generate the new proto module content
    new_proto_content = generate_proto_module_content(package_structure)

    # Replace only the proto module section
    before_proto = content[:proto_start]
    after_proto = content[proto_end + 1:]  # +1 to skip the closing brace

    # Reconstruct the file
    new_content = before_proto + new_proto_content + after_proto

    # Write back to file
    with open(lib_rs_path, 'w') as f:
        f.write(new_content)

    return True

def generate_proto_module_content(package_structure: Dict[str, List[str]]) -> str:
    """Generate only the proto module content."""
    lines = [
        "pub mod proto {",
    ]

    # Sort main modules for consistent output
    for main_module in sorted(package_structure.keys()):
        packages = package_structure[main_module]

        if len(packages) == 1 and packages[0] == f"starknet.{main_module}":
            # Simple case: starknet.common -> pub mod common
            lines.append("")
            if main_module in ['class', 'consensus', 'header', 'receipt', 'transaction']:
                lines.append("    #[allow(clippy::large_enum_variant)]")
            lines.append(f"    pub mod {main_module} {{")
            lines.append(f"        include!(concat!(env!(\"OUT_DIR\"), \"/starknet.{main_module}.rs\"));")
            lines.append("    }")
        else:
            # Complex case: nested modules like starknet.sync.class
            lines.append("")
            lines.append(f"    pub mod {main_module} {{")

            # Sort nested packages for consistent output
            nested_packages = sorted(packages)

            # First, include the main module file if it exists
            main_package = f"starknet.{main_module}"
            if main_package in packages:
                lines.append(f"        include!(concat!(env!(\"OUT_DIR\"), \"/{main_package}.rs\"));")

            # Then add nested modules
            for package in nested_packages:
                if package != main_package:
                    # This is a nested module
                    nested_module = package.replace(f"starknet.{main_module}.", "")

                    # Check if this module might have large enums (common ones)
                    is_large_enum = nested_module in ['header', 'receipt', 'transaction', 'class']

                    lines.append(generate_module_declaration(package, is_large_enum))

            lines.append("    }")

    lines.append("}")

    return "\n".join(lines)

def main():
    print("🔍 Analyzing generated proto structure...")

    # Analyze the generated files
    package_structure = analyze_proto_files()

    if not package_structure:
        print("❌ No package structure found. Make sure to run the proto sync script first.")
        return

    print("📦 Found package structure:")
    for main_module, packages in package_structure.items():
        print(f"  {main_module}: {packages}")

    # Update the lib.rs file (preserving existing content)
    lib_rs_path = Path("src/lib.rs")

    if update_lib_rs_file(package_structure, lib_rs_path):
        print("✅ lib.rs updated successfully!")
        print("\n📋 Updated proto module structure:")
        print(generate_proto_module_content(package_structure))
    else:
        print("❌ Failed to update lib.rs")

if __name__ == "__main__":
    main()
