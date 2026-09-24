use super::BwrapOptions;
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
    let args = create_filesystem_args(&policy, temp.path(), BwrapOptions::default())
        .expect("filesystem arguments");

    let daemon_directory = codex_uds::shared_daemon_socket_directory().expect("daemon directory");
    assert_eq!(
        args.args,
        ["--ro-bind", "/", "/", "--dev", "/dev", "--perms", "000", "--tmpfs"]
            .into_iter()
            .map(str::to_owned)
            .chain([
                daemon_directory.display().to_string(),
                "--remount-ro".to_owned(),
                daemon_directory.display().to_string(),
                "--bind".to_owned(),
                target.display().to_string(),
                target.display().to_string(),
            ])
            .collect::<Vec<_>>()
    );
    assert!(args.synthetic_mount_targets.is_empty());
    assert!(args.protected_create_targets.is_empty());
}

#[test]
fn readable_file_below_denied_parent_keeps_wslg_mask_last() {
    let temp = tempfile::tempdir().expect("tempdir");
    let target = temp.path().join("allowed.txt");
    std::fs::write(&target, "fixture").expect("write fixture");
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry::new(
            FileSystemPath::Special { value: FileSystemSpecialPath::Root },
            FileSystemAccessMode::Read,
        ),
        FileSystemSandboxEntry::new(
            AbsolutePathBuf::from_absolute_path(temp.path()).expect("absolute parent").into(),
            FileSystemAccessMode::Deny,
        ),
        FileSystemSandboxEntry::new(
            AbsolutePathBuf::from_absolute_path(&target).expect("absolute file").into(),
            FileSystemAccessMode::Read,
        ),
    ]);
    let args = create_filesystem_args(&policy, temp.path(), BwrapOptions {
        mask_wslg_distro: true,
        ..Default::default()
    }).expect("filesystem arguments").args;
    let target = target.display().to_string();
    assert_eq!(
        &args[args.len() - 9..],
        ["--ro-bind", &target, &target, "--perms", "000", "--tmpfs",
            super::WSLG_DISTRO_ROOT, "--remount-ro", super::WSLG_DISTRO_ROOT]
    );
}

#[test]
fn readable_file_below_denied_daemon_directory_is_rejected() {
    let daemon_directory = codex_uds::prepare_shared_daemon_socket_directory().expect("daemon directory");
    let temp = tempfile::tempdir_in(&daemon_directory).expect("private fixture directory");
    let target = temp.path().join("file");
    std::fs::write(&target, "fixture").expect("write fixture");
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry::new(
            FileSystemPath::Special { value: FileSystemSpecialPath::Root },
            FileSystemAccessMode::Read,
        ),
        FileSystemSandboxEntry::new(
            AbsolutePathBuf::from_absolute_path(temp.path()).expect("absolute parent").into(),
            FileSystemAccessMode::Deny,
        ),
        FileSystemSandboxEntry::new(
            AbsolutePathBuf::from_absolute_path(target).expect("absolute file").into(),
            FileSystemAccessMode::Read,
        ),
    ]);
    let error = create_filesystem_args(&policy, temp.path(), BwrapOptions::default())
        .expect_err("daemon files must remain inaccessible");
    assert_eq!(error.to_string(), "app-server socket directory cannot be a sandbox mount root");
}
