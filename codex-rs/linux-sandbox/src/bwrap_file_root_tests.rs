use super::create_filesystem_args;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_protocol::permissions::FileSystemSpecialPath;
use codex_utils_absolute_path::AbsolutePathBuf;
use pretty_assertions::assert_eq;

#[test]
fn writable_file_root_has_no_metadata_descendants() {
    let temp = tempfile::tempdir().expect("tempdir");
    let target = temp.path().join("config.toml");
    std::fs::write(&target, "fixture").expect("write fixture");
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry::new(
            FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            FileSystemAccessMode::Read,
        ),
        FileSystemSandboxEntry::new(
            AbsolutePathBuf::from_absolute_path(&target)
                .expect("absolute file")
                .into(),
            FileSystemAccessMode::Write,
        ),
    ]);
    let args = create_filesystem_args(&policy, temp.path(), /*glob_scan_max_depth*/ None)
        .expect("filesystem arguments");

    assert_eq!(
        args.args,
        ["--ro-bind", "/", "/", "--dev", "/dev", "--bind"]
            .into_iter()
            .map(str::to_owned)
            .chain([target.display().to_string(), target.display().to_string()])
            .collect::<Vec<_>>()
    );
    assert!(args.synthetic_mount_targets.is_empty());
    assert!(args.protected_create_targets.is_empty());
}
