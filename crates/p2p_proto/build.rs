use std::io::Result;
use std::path::Path;

fn main() -> Result<()> {
    let proto_dir = "proto";
    let mut proto_files = Vec::new();

    // Collect all proto files
    collect_proto_files(proto_dir, &mut proto_files)?;

    // Sort for consistent builds
    proto_files.sort();

    // Use "." as the include path so that "proto/..." imports resolve correctly
    // The proto files are in the proto/ directory, so "." as include path works
    prost_build::compile_protos(&proto_files, &["."])?;

    Ok(())
}

fn collect_proto_files(dir: &str, files: &mut Vec<String>) -> Result<()> {
    let path = Path::new(dir);

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();

        if entry_path.is_file() && entry_path.extension().map_or(false, |ext| ext == "proto") {
            // Add the full path from the current directory
            let file_path = entry_path.to_string_lossy().to_string();
            files.push(file_path);
        } else if entry_path.is_dir() {
            // Recursively search subdirectories
            let subdir = entry_path.to_str().unwrap();
            collect_proto_files(subdir, files)?;
        }
    }

    Ok(())
}
