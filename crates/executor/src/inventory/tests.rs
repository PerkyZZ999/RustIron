//! Benign local metadata fixtures only; no archive, PHP/SQL execution or network.
use super::*;
use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
/// The site below a restore target, as the probe fetch lays it out:
/// `<base>/restore/srv/sites/rs_fixture/{html,tmp/rustiron-capture.sql}`.
/// `.0` is the site directory, `.1` the restore target, `.2` the base.
struct Site(PathBuf, PathBuf, PathBuf);
const SITE: &str = "srv/sites/rs_fixture";
impl Site {
    fn new() -> Self {
        assert_ne!(rustix::process::geteuid().as_raw(), 0);
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::temp_dir().join(format!(
            "ri-inventory-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&base)
            .unwrap();
        let restore = base.join("restore");
        let root = restore.join(SITE);
        std::fs::create_dir_all(root.join("html")).unwrap();
        std::fs::create_dir(root.join("tmp")).unwrap();
        std::fs::write(
            root.join("tmp/rustiron-capture.sql"),
            b"BENIGN_METADATA_FIXTURE",
        )
        .unwrap();
        Self(root, restore, base)
    }
    fn run(&self, limits: Limits) -> Report {
        inventory(&self.1, Path::new(SITE), limits)
    }
}
impl Drop for Site {
    fn drop(&mut self) {
        let hidden = self.0.join("html/unreadable");
        if hidden.exists() {
            std::fs::set_permissions(hidden, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::remove_dir_all(&self.2).unwrap();
    }
}
#[test]
fn complete_tree_counts_regular_files_and_dump() {
    let site = Site::new();
    std::fs::create_dir(site.0.join("html/sub")).unwrap();
    std::fs::write(site.0.join("html/one"), b"fixture").unwrap();
    std::fs::write(site.0.join("html/sub/two"), b"fixture").unwrap();
    let r = site.run(Limits::default());
    assert_eq!(r.status, Status::Complete);
    assert_eq!(r.files, Some(2));
    assert_eq!(r.entries, 3);
    assert_eq!(r.dump, Some(true));
    assert_eq!(r.max_depth, 1);
}
#[test]
fn empty_tree_is_complete_zero_not_an_error() {
    let r = Site::new().run(Limits::default());
    assert_eq!(r.status, Status::Complete);
    assert_eq!(r.files, Some(0));
}
#[test]
fn missing_dump_is_observed_false() {
    let site = Site::new();
    std::fs::remove_file(site.0.join("tmp/rustiron-capture.sql")).unwrap();
    let r = site.run(Limits::default());
    assert_eq!(r.status, Status::Complete);
    assert_eq!(r.dump, Some(false));
}
#[test]
fn unreadable_subtree_never_returns_partial_success() {
    let site = Site::new();
    std::fs::write(site.0.join("html/visible"), b"fixture").unwrap();
    std::fs::create_dir(site.0.join("html/unreadable")).unwrap();
    std::fs::set_permissions(
        site.0.join("html/unreadable"),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    let r = site.run(Limits::default());
    assert_eq!(r.status, Status::Error);
    assert_eq!(r.reason, Some(Reason::Io));
    assert_eq!(r.files, None);
    assert_eq!(r.dump, None);
}
#[test]
fn missing_html_is_an_error() {
    let site = Site::new();
    std::fs::remove_dir(site.0.join("html")).unwrap();
    let r = site.run(Limits::default());
    assert_eq!(r.status, Status::Error);
    assert_eq!(r.files, None);
}
#[test]
fn missing_tmp_is_an_error() {
    let site = Site::new();
    std::fs::remove_dir_all(site.0.join("tmp")).unwrap();
    let r = site.run(Limits::default());
    assert_eq!(r.status, Status::Error);
    assert_eq!(r.dump, None);
}
#[test]
fn entry_limit_cannot_look_complete() {
    let site = Site::new();
    std::fs::write(site.0.join("html/a"), b"fixture").unwrap();
    std::fs::write(site.0.join("html/b"), b"fixture").unwrap();
    let r = site.run(Limits {
        entries: 1,
        ..Limits::default()
    });
    assert_eq!(r.status, Status::Limit);
    assert_eq!(r.reason, Some(Reason::Entries));
    assert_eq!(r.files, None);
    assert_eq!(r.entries, 1);
}
#[test]
fn exact_entry_limit_can_complete() {
    let site = Site::new();
    std::fs::write(site.0.join("html/a"), b"fixture").unwrap();
    let r = site.run(Limits {
        entries: 1,
        ..Limits::default()
    });
    assert_eq!(r.status, Status::Complete);
    assert_eq!(r.files, Some(1));
}
#[test]
fn depth_limit_cannot_look_complete() {
    let site = Site::new();
    std::fs::create_dir_all(site.0.join("html/a/b")).unwrap();
    let r = site.run(Limits {
        depth: 1,
        ..Limits::default()
    });
    assert_eq!(r.status, Status::Limit);
    assert_eq!(r.reason, Some(Reason::Depth));
    assert_eq!(r.files, None);
    assert_eq!(r.max_depth, 1);
}
#[test]
fn exact_depth_limit_can_complete() {
    let site = Site::new();
    std::fs::create_dir(site.0.join("html/a")).unwrap();
    std::fs::write(site.0.join("html/a/file"), b"fixture").unwrap();
    let r = site.run(Limits {
        depth: 1,
        ..Limits::default()
    });
    assert_eq!(r.status, Status::Complete);
    assert_eq!(r.files, Some(1));
}
#[test]
fn expired_budget_returns_limit_before_opening_input() {
    let r = inventory(
        Path::new("/missing/benign-fixture"),
        Path::new(SITE),
        Limits {
            time: Duration::ZERO,
            ..Limits::default()
        },
    );
    assert_eq!(r.status, Status::Limit);
    assert_eq!(r.reason, Some(Reason::Time));
    assert_eq!(r.entries, 0);
}
#[test]
fn relative_input_is_refused() {
    let r = inventory(
        Path::new("relative-fixture"),
        Path::new(SITE),
        Limits::default(),
    );
    assert_eq!(r.status, Status::Error);
    assert_eq!(r.reason, Some(Reason::Unsupported));
}
#[test]
fn non_utf8_entry_names_do_not_enter_reports() {
    use std::os::unix::ffi::OsStringExt;
    let site = Site::new();
    std::fs::write(
        site.0
            .join("html")
            .join(std::ffi::OsString::from_vec(vec![0xff])),
        b"fixture",
    )
    .unwrap();
    let r = site.run(Limits::default());
    assert_eq!(r.status, Status::Complete);
    assert_eq!(r.files, Some(1));
}
#[test]
fn root_identity_is_refused_before_walk() {
    let site = Site::new();
    let r = inventory_with_identity(&site.1, Path::new(SITE), Limits::default(), 0, 0);
    assert_eq!(r.reason, Some(Reason::Identity));
    assert_eq!(r.files, None);
    assert_eq!(r.entries, 0);
}
#[test]
fn mixed_identity_is_refused_before_walk() {
    let site = Site::new();
    let r = inventory_with_identity(&site.1, Path::new(SITE), Limits::default(), 1000, 0);
    assert_eq!(r.reason, Some(Reason::Identity));
    assert_eq!(r.entries, 0);
}

#[test]
fn search_only_ancestor_of_the_restore_target_does_not_require_listing() {
    // The sandbox root above `tmp/restore` is root-owned 0751 on the host.
    let site = Site::new();
    std::fs::write(site.0.join("html/one"), b"fixture").unwrap();
    std::fs::set_permissions(&site.2, std::fs::Permissions::from_mode(0o111)).unwrap();
    let report = site.run(Limits::default());
    std::fs::set_permissions(&site.2, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(report.status, Status::Complete);
    assert_eq!(report.files, Some(1));
    assert_eq!(report.dump, Some(true));
    assert_eq!(report.extra_paths, Some(0));
}
/// W378 (W328 c4b): a snapshot path outside the site's html and dump is
/// restored inside the sandbox; the report counts each one where it first
/// leaves the captured paths and never descends into it.
#[test]
fn entries_outside_the_captured_site_paths_are_counted() {
    let site = Site::new();
    std::fs::write(site.0.join("html/one"), b"fixture").unwrap();
    for dir in ["mnt/w378-extra/deep", "srv/sites/rs_other/html"] {
        std::fs::create_dir_all(site.1.join(dir)).unwrap();
    }
    std::fs::write(site.1.join("mnt/w378-extra/deep/f"), b"fixture").unwrap();
    std::fs::write(site.1.join("top-file"), b"fixture").unwrap();
    std::fs::create_dir(site.0.join("private")).unwrap();
    std::fs::write(site.0.join("private/db.cnf"), b"fixture").unwrap();
    std::fs::write(site.0.join("tmp/other.sql"), b"fixture").unwrap();
    std::os::unix::fs::symlink("/etc", site.1.join("srv/link")).unwrap();
    let r = site.run(Limits::default());
    assert_eq!(r.status, Status::Complete);
    assert_eq!(r.files, Some(1));
    assert_eq!(r.dump, Some(true));
    // mnt, top-file, srv/link, srv/sites/rs_other, private, tmp/other.sql.
    assert_eq!(r.extra_paths, Some(6));
    assert_eq!(r.entries, 7);
    assert_eq!(Site::new().run(Limits::default()).extra_paths, Some(0));
}
#[test]
fn extra_paths_share_the_entry_limit() {
    let site = Site::new();
    std::fs::write(site.0.join("html/one"), b"fixture").unwrap();
    std::fs::write(site.1.join("a"), b"fixture").unwrap();
    std::fs::write(site.1.join("b"), b"fixture").unwrap();
    let r = site.run(Limits {
        entries: 2,
        ..Limits::default()
    });
    assert_eq!(r.status, Status::Limit);
    assert_eq!(r.reason, Some(Reason::Entries));
    assert_eq!(r.extra_paths, None);
}
#[test]
fn an_unlistable_directory_on_the_site_path_is_an_error() {
    // The restore tree must be listed to know whether it holds extra paths.
    let site = Site::new();
    let srv = site.1.join("srv");
    std::fs::set_permissions(&srv, std::fs::Permissions::from_mode(0o111)).unwrap();
    let r = site.run(Limits::default());
    std::fs::set_permissions(&srv, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(r.status, Status::Error);
    assert_eq!(r.reason, Some(Reason::Io));
    assert_eq!(r.extra_paths, None);
}
#[test]
fn a_site_path_that_is_not_plain_names_is_refused() {
    let site = Site::new();
    for path in [
        "",
        "/srv/sites/rs_fixture",
        "srv/../srv/sites/rs_fixture",
        "./srv",
    ] {
        let r = inventory(&site.1, Path::new(path), Limits::default());
        assert_eq!(r.status, Status::Error, "{path:?}");
        assert_eq!(r.reason, Some(Reason::Unsupported), "{path:?}");
    }
}
#[test]
fn a_linked_directory_on_the_site_path_is_an_error() {
    let site = Site::new();
    std::fs::rename(site.1.join("srv"), site.2.join("srv-real")).unwrap();
    std::os::unix::fs::symlink(site.2.join("srv-real"), site.1.join("srv")).unwrap();
    let r = site.run(Limits::default());
    assert_eq!(r.status, Status::Error);
    assert_eq!(r.files, None);
}
/// W221 (B03, unprivileged): the hostile file types of W179 are refused by the
/// walk itself, not only by SELinux at fetch time; none can look complete.
#[test]
fn hostile_file_types_never_look_complete() {
    use std::os::unix::fs::symlink;
    type Plant = fn(&std::path::Path);
    let cases: &[(&str, Plant)] = &[
        ("symlink to /etc", |s| {
            symlink("/etc", s.join("html/etc")).unwrap()
        }),
        ("dangling symlink", |s| {
            symlink("../../nowhere", s.join("html/x")).unwrap()
        }),
        ("symlink loop", |s| {
            symlink("loop", s.join("html/loop")).unwrap()
        }),
        ("fifo", |s| {
            rustix::fs::mknodat(
                rustix::fs::CWD,
                s.join("html/f"),
                FileType::Fifo,
                Mode::from_raw_mode(0o600),
                0,
            )
            .unwrap()
        }),
        ("unix socket", |s| {
            std::mem::forget(std::os::unix::net::UnixListener::bind(s.join("html/sock")).unwrap());
        }),
        ("hardlink pair", |s| {
            std::fs::write(s.join("html/a"), b"fixture").unwrap();
            std::fs::hard_link(s.join("html/a"), s.join("html/b")).unwrap();
        }),
        ("html is a symlink", |s| {
            std::fs::remove_dir(s.join("html")).unwrap();
            symlink("/etc", s.join("html")).unwrap();
        }),
        ("tmp is a symlink", |s| {
            std::fs::remove_dir_all(s.join("tmp")).unwrap();
            symlink("/etc", s.join("tmp")).unwrap();
        }),
        ("dump is a symlink", |s| {
            std::fs::remove_file(s.join("tmp/rustiron-capture.sql")).unwrap();
            symlink("/etc/passwd", s.join("tmp/rustiron-capture.sql")).unwrap();
        }),
        ("dump is hardlinked", |s| {
            std::fs::hard_link(s.join("tmp/rustiron-capture.sql"), s.join("tmp/other")).unwrap();
        }),
        ("dump is a fifo", |s| {
            std::fs::remove_file(s.join("tmp/rustiron-capture.sql")).unwrap();
            rustix::fs::mknodat(
                rustix::fs::CWD,
                s.join("tmp/rustiron-capture.sql"),
                FileType::Fifo,
                Mode::from_raw_mode(0o600),
                0,
            )
            .unwrap();
        }),
    ];
    for (name, plant) in cases {
        let site = Site::new();
        plant(&site.0);
        let r = site.run(Limits::default());
        assert_ne!(r.status, Status::Complete, "{name}");
        assert_eq!(r.files, None, "{name}");
        assert_eq!(r.dump, None, "{name}");
    }
}
/// W222 (owner decision): setuid/setgid regular files are refused; files
/// writable by others are counted and reported but not refused.
#[test]
fn setuid_and_setgid_files_are_refused() {
    for (name, mode, in_tmp) in [
        ("setuid", 0o4755, false),
        ("setgid", 0o2755, false),
        ("setuid dump", 0o4600, true),
    ] {
        let site = Site::new();
        let path = if in_tmp {
            site.0.join("tmp/rustiron-capture.sql")
        } else {
            site.0.join("html/x")
        };
        std::fs::write(&path, b"fixture").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let r = site.run(Limits::default());
        assert_eq!(r.status, Status::Error, "{name}");
        assert_eq!(r.reason, Some(Reason::Privileged), "{name}");
        assert_eq!(r.files, None, "{name}");
        assert_eq!(r.world_writable, None, "{name}");
    }
}
/// W383 (D-034, W378 s6): a setgid or setuid directory is refused too. W378
/// restored a 02755 folder that the inventory did not refuse.
#[test]
fn setuid_and_setgid_directories_are_refused() {
    for (dir, mode) in [("html", 0o2755), ("html/sub", 0o2755), ("html/sub", 0o4755)] {
        let site = Site::new();
        std::fs::create_dir(site.0.join("html/sub")).unwrap();
        std::fs::write(site.0.join("html/sub/a"), b"fixture").unwrap();
        std::fs::set_permissions(site.0.join(dir), std::fs::Permissions::from_mode(mode)).unwrap();
        let r = site.run(Limits::default());
        std::fs::set_permissions(site.0.join(dir), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(r.status, Status::Error, "{dir} {mode:o}");
        assert_eq!(r.reason, Some(Reason::Privileged), "{dir} {mode:o}");
        assert_eq!(r.files, None, "{dir} {mode:o}");
    }
}
#[test]
fn world_writable_files_are_counted_not_refused() {
    let site = Site::new();
    std::fs::create_dir(site.0.join("html/sub")).unwrap();
    for (path, mode) in [("html/a", 0o777), ("html/sub/b", 0o666), ("html/c", 0o644)] {
        std::fs::write(site.0.join(path), b"fixture").unwrap();
        std::fs::set_permissions(site.0.join(path), std::fs::Permissions::from_mode(mode)).unwrap();
    }
    let r = site.run(Limits::default());
    assert_eq!(r.status, Status::Complete);
    assert_eq!(r.files, Some(3));
    assert_eq!(r.world_writable, Some(2));
}
#[test]
fn world_writable_directories_are_refused() {
    // W230 h8: 0777 html and wp-content were restored with no signal.
    for dir in ["html", "html/sub"] {
        let site = Site::new();
        std::fs::create_dir(site.0.join("html/sub")).unwrap();
        std::fs::write(site.0.join("html/sub/a"), b"fixture").unwrap();
        std::fs::set_permissions(site.0.join(dir), std::fs::Permissions::from_mode(0o777)).unwrap();
        let r = site.run(Limits::default());
        std::fs::set_permissions(site.0.join(dir), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(r.status, Status::Error, "{dir}");
        assert_eq!(r.reason, Some(Reason::WorldWritableDirectory), "{dir}");
        assert_eq!(r.files, None, "{dir}");
    }
}
