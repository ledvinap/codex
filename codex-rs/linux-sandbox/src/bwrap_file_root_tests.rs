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
fn deny_glob_wins_over_exact_file_grants_below_denied_parent() {
    let temp = tempfile::tempdir().expect("tempdir");
    let parent = temp.path().join("private");
    std::fs::create_dir(&parent).expect("create parent");
    let target = parent.join("config.toml");
    std::fs::write(&target, "fixture").expect("write fixture");

    for access in [FileSystemAccessMode::Read, FileSystemAccessMode::Write] {
        let policy = FileSystemSandboxPolicy::restricted(vec![
            FileSystemSandboxEntry::new(
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::Root,
                },
                FileSystemAccessMode::Read,
            ),
            FileSystemSandboxEntry::new(
                AbsolutePathBuf::from_absolute_path(&parent)
                    .expect("absolute parent")
                    .into(),
                FileSystemAccessMode::Deny,
            ),
            FileSystemSandboxEntry::new(
                AbsolutePathBuf::from_absolute_path(&target)
                    .expect("absolute file")
                    .into(),
                access,
            ),
            FileSystemSandboxEntry::new(
                FileSystemPath::GlobPattern {
                    pattern: format!("{}/*.toml", parent.display()),
                },
                FileSystemAccessMode::Deny,
            ),
        ]);
        let args = create_filesystem_args(&policy, temp.path(), BwrapOptions::default())
            .expect("filesystem arguments");
        let target = target.display().to_string();
        let placeholder_index = args
            .args
            .windows(3)
            .position(|window| window == ["--ro-bind", "/dev/null", &target])
            .expect("file target must exist before the denied parent becomes read-only");
        let mask_index = args
            .args
            .windows(5)
            .position(|window| {
                window[0] == "--perms"
                    && window[1] == "000"
                    && window[2] == "--ro-bind-data"
                    && window[4] == target
            })
            .expect("glob must mask the exact file");
        assert!(placeholder_index < mask_index, "access: {access:?}");
        assert!(
            !args.args.windows(3).enumerate().any(|(index, window)| {
                index > mask_index
                    && matches!(window[0].as_str(), "--bind" | "--ro-bind")
                    && window[1] == target
                    && window[2] == target
            }),
            "file must remain masked after all grants, access: {access:?}, args: {:?}",
            args.args
        );
    }
}

#[test]
fn denied_aliases_do_not_reopen_readable_files_below_denied_parent() {
    let temp = tempfile::tempdir().expect("tempdir");
    let parent = temp.path().join("private");
    std::fs::create_dir(&parent).expect("create parent");
    let target = parent.join("config.toml");
    std::fs::write(&target, "fixture").expect("write fixture");

    for (name, alias_target) in [("file-link", &target), ("directory-link", &parent)] {
        let alias = temp.path().join(name);
        std::os::unix::fs::symlink(alias_target, &alias).expect("create denied alias");
        let policy = FileSystemSandboxPolicy::restricted(vec![
            FileSystemSandboxEntry::new(
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::Root,
                },
                FileSystemAccessMode::Read,
            ),
            FileSystemSandboxEntry::new(
                AbsolutePathBuf::from_absolute_path(&parent)
                    .expect("absolute parent")
                    .into(),
                FileSystemAccessMode::Deny,
            ),
            FileSystemSandboxEntry::new(
                AbsolutePathBuf::from_absolute_path(&target)
                    .expect("absolute file")
                    .into(),
                FileSystemAccessMode::Read,
            ),
            FileSystemSandboxEntry::new(
                AbsolutePathBuf::from_absolute_path(&alias)
                    .expect("absolute alias")
                    .into(),
                FileSystemAccessMode::Deny,
            ),
        ]);
        let args = create_filesystem_args(&policy, temp.path(), BwrapOptions::default())
            .expect("filesystem arguments");
        let target = target.display().to_string();
        assert!(
            !args.args.windows(3).any(|window| {
                window == ["--ro-bind", &target, &target]
                    || window == ["--ro-bind", "/dev/null", &target]
            }),
            "denied alias must not be reopened through a file or placeholder, alias: {name}, args: {:?}",
            args.args
        );
    }
}

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
    let daemon_directories = crate::daemon_mounts::daemon_socket_mask_paths(
        &daemon_directory,
        /*masked_root*/ None,
    )
    .expect("daemon aliases");
    let mut expected = ["--ro-bind", "/", "/", "--dev", "/dev"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for directory in daemon_directories {
        expected.extend([
            "--perms".to_owned(),
            "000".to_owned(),
            "--tmpfs".to_owned(),
            directory.display().to_string(),
            "--remount-ro".to_owned(),
            directory.display().to_string(),
        ]);
    }
    expected.extend([
        "--bind".to_owned(),
        target.display().to_string(),
        target.display().to_string(),
    ]);
    assert_eq!(args.args, expected);
    assert!(args.synthetic_mount_targets.is_empty());
}

#[test]
fn readable_file_below_denied_parent_keeps_wslg_mask_last() {
    let temp = tempfile::tempdir().expect("tempdir");
    let target = temp.path().join("allowed.txt");
    std::fs::write(&target, "fixture").expect("write fixture");
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry::new(
            FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            FileSystemAccessMode::Read,
        ),
        FileSystemSandboxEntry::new(
            AbsolutePathBuf::from_absolute_path(temp.path())
                .expect("absolute parent")
                .into(),
            FileSystemAccessMode::Deny,
        ),
        FileSystemSandboxEntry::new(
            AbsolutePathBuf::from_absolute_path(&target)
                .expect("absolute file")
                .into(),
            FileSystemAccessMode::Read,
        ),
    ]);
    let args = create_filesystem_args(
        &policy,
        temp.path(),
        BwrapOptions {
            mask_wslg_distro: true,
            ..Default::default()
        },
    )
    .expect("filesystem arguments")
    .args;
    let target = target.display().to_string();
    assert_eq!(
        &args[args.len() - 9..],
        [
            "--ro-bind",
            &target,
            &target,
            "--perms",
            "000",
            "--tmpfs",
            super::WSLG_DISTRO_ROOT,
            "--remount-ro",
            super::WSLG_DISTRO_ROOT
        ]
    );
}

#[test]
fn readable_file_below_denied_daemon_directory_is_rejected() {
    let daemon_directory =
        codex_uds::prepare_shared_daemon_socket_directory().expect("daemon directory");
    let temp = tempfile::tempdir_in(&daemon_directory).expect("private fixture directory");
    let target = temp.path().join("file");
    std::fs::write(&target, "fixture").expect("write fixture");
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry::new(
            FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            FileSystemAccessMode::Read,
        ),
        FileSystemSandboxEntry::new(
            AbsolutePathBuf::from_absolute_path(temp.path())
                .expect("absolute parent")
                .into(),
            FileSystemAccessMode::Deny,
        ),
        FileSystemSandboxEntry::new(
            AbsolutePathBuf::from_absolute_path(target)
                .expect("absolute file")
                .into(),
            FileSystemAccessMode::Read,
        ),
    ]);
    let error = create_filesystem_args(&policy, temp.path(), BwrapOptions::default())
        .expect_err("daemon files must remain inaccessible");
    assert_eq!(
        error.to_string(),
        "Fatal error: app-server socket directory cannot be a sandbox mount root"
    );
}
