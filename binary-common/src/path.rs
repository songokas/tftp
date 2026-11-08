use std::path::Component;
use std::path::Path;

use tftp_dus::error::FileError;
use tftp_dus::types::FilePath;

pub fn validate_path(requested_path: &FilePath, max_depth: usize) -> Result<(), FileError> {
    let component_count = Path::new(requested_path.as_str())
        .components()
        .filter(|c| {
            matches!(
                c,
                Component::Normal(_) | Component::ParentDir | Component::CurDir
            )
        })
        .count();
    if component_count.saturating_sub(1) <= max_depth {
        return Ok(());
    }
    Err(FileError::InvalidFileName)
}

pub fn file_name(path: &FilePath) -> Result<FilePath, &'static str> {
    Path::new(path.as_str())
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.parse().ok())
        .ok_or("Invalid file name")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_path() {
        let data = [
            ("filename", 0, true),
            ("filename", 1, true),
            ("dir/file", 0, false),
            ("dir/file", 1, true),
            ("/file", 1, true),
            ("", 1, true),
            ("../../a", 1, false),
            ("../../a", 3, true),
        ];
        for (p, count, result) in data {
            let p: FilePath = p.parse().unwrap();
            assert_eq!(validate_path(&p, count).is_ok(), result, "{p} {count}");
        }
    }

    #[test]
    fn test_file_name() {
        let path: FilePath = "dir/file".parse().unwrap();
        assert_eq!(file_name(&path).unwrap().as_str(), "file");
        let path: FilePath = "..".parse().unwrap();
        assert!(file_name(&path).is_err());
    }
}
