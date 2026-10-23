use super::*;
use codex_protocol::protocol::FileSystemSandboxEntry;
use pretty_assertions::assert_eq;
use tempfile::TempDir;
use test_case::test_case;

fn path_entry(path: &Path, access: FileSystemAccessMode) -> FileSystemSandboxEntry {
    FileSystemSandboxEntry::new(
        AbsolutePathBuf::try_from(path)
            .expect("absolute path")
            .into(),
        access,
    )
}

#[test_case(FileSystemAccessMode::Read; "restricted_read")]
#[test_case(FileSystemAccessMode::Write; "restricted_write")]
#[test_case(FileSystemAccessMode::Deny; "denied")]
fn character_device_bind_requires_explicit_write(access: FileSystemAccessMode) {
    let policy =
        FileSystemSandboxPolicy::restricted(vec![path_entry(Path::new("/dev/null"), access)]);
    let args = create_filesystem_args(&policy, Path::new("/"), BwrapOptions::default())
        .expect("filesystem args")
        .args;
    let device_binds: Vec<_> = args
        .windows(3)
        .filter(|args| args[0] == "--dev-bind")
        .map(<[String]>::to_vec)
        .collect();
    let expected = if access == FileSystemAccessMode::Write {
        vec![vec!["--dev-bind", "/dev/null", "/dev/null"]]
    } else {
        vec![]
    };
    assert_eq!(device_binds, expected);
}

#[test]
fn explicit_character_device_bind_follows_minimal_dev_with_full_read() {
    let mut policy = FileSystemSandboxPolicy::default();
    policy.entries.push(path_entry(
        Path::new("/dev/null"),
        FileSystemAccessMode::Write,
    ));
    let args = create_filesystem_args(&policy, Path::new("/"), BwrapOptions::default())
        .expect("filesystem args")
        .args;
    let minimal_dev = args
        .windows(2)
        .position(|args| args == ["--dev", "/dev"])
        .expect("minimal device tree");
    let device_bind = args
        .windows(3)
        .position(|args| args == ["--dev-bind", "/dev/null", "/dev/null"])
        .expect("exact device bind");
    assert!(minimal_dev < device_bind);
    assert!(!args.iter().any(|arg| arg.starts_with("/dev/null/")));
}

#[test]
fn directory_grant_does_not_enable_contained_devices() {
    let policy = FileSystemSandboxPolicy::restricted(vec![path_entry(
        Path::new("/dev"),
        FileSystemAccessMode::Write,
    )]);
    let args = create_filesystem_args(&policy, Path::new("/"), BwrapOptions::default())
        .expect("filesystem args")
        .args;
    assert!(!args.iter().any(|arg| arg == "--dev-bind"));
    assert!(
        args.windows(3)
            .any(|args| args == ["--bind", "/dev", "/dev"])
    );
}

#[test]
fn regular_file_grant_uses_ordinary_bind() {
    let temp = TempDir::new().expect("temp dir");
    let file = temp.path().join("file");
    fs::write(&file, "contents").expect("create file");
    let policy =
        FileSystemSandboxPolicy::restricted(vec![path_entry(&file, FileSystemAccessMode::Write)]);
    let args = create_filesystem_args(&policy, temp.path(), BwrapOptions::default())
        .expect("filesystem args")
        .args;
    assert!(!args.iter().any(|arg| arg == "--dev-bind"));
    assert!(
        args.windows(3)
            .any(|args| args == ["--bind", &path_to_string(&file), &path_to_string(&file)])
    );
}
