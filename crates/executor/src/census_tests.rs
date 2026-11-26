//! Unprivileged boundary and race tests for the ownership census (W210).
use super::*;
use std::{fs as stdfs, os::unix::fs::symlink, path::Path};

fn me() -> u32 {
    rustix::process::getuid().as_raw()
}

fn open(path: &Path) -> OwnedFd {
    fs::open(path, DIRECTORY, Mode::empty()).unwrap()
}

struct Base(std::path::PathBuf);
impl Base {
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Base {
    fn drop(&mut self) {
        let _ = stdfs::remove_dir_all(&self.0);
    }
}

fn tree() -> (Base, std::path::PathBuf) {
    assert_ne!(rustix::process::geteuid().as_raw(), 0);
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let base = Base(std::env::temp_dir().join(format!(
        "ri-census-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )));
    stdfs::create_dir(base.path()).unwrap();
    let html = base.path().join("html");
    stdfs::create_dir_all(html.join("wp-includes/js")).unwrap();
    stdfs::write(html.join("index.php"), "x").unwrap();
    stdfs::write(html.join("wp-includes/version.php"), "x").unwrap();
    stdfs::write(html.join("wp-includes/js/a.js"), "x").unwrap();
    (base, html)
}

#[test]
fn counts_owned_regular_files() {
    let (_base, html) = tree();
    let found = census(&open(&html), me(), BOUNDS).unwrap();
    assert_eq!(
        found,
        Census {
            owned_files: 3,
            foreign: 0,
            mislabelled: 0
        }
    );
}

#[test]
fn other_owner_is_foreign() {
    let (_base, html) = tree();
    let found = census(&open(&html), me() + 1, BOUNDS).unwrap();
    assert_eq!(found.owned_files, 0);
    assert_eq!(found.foreign, 5);
}

#[test]
fn symlinks_are_foreign_and_never_followed() {
    let (base, html) = tree();
    let outside = base.path().join("outside");
    stdfs::create_dir(&outside).unwrap();
    for n in 0..5 {
        stdfs::write(outside.join(format!("{n}")), "x").unwrap();
    }
    symlink(&outside, html.join("escape")).unwrap();
    symlink("/etc/passwd", html.join("wp-includes/passwd")).unwrap();
    let found = census(&open(&html), me(), BOUNDS).unwrap();
    assert_eq!(
        found,
        Census {
            owned_files: 3,
            foreign: 2,
            mislabelled: 0
        }
    );
}

#[test]
fn hard_links_and_fifos_are_foreign() {
    let (_base, html) = tree();
    stdfs::hard_link(html.join("index.php"), html.join("linked.php")).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        html.join("pipe"),
        FileType::Fifo,
        Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let found = census(&open(&html), me(), BOUNDS).unwrap();
    assert_eq!(
        found,
        Census {
            owned_files: 2,
            foreign: 3,
            mislabelled: 0
        }
    );
}

#[test]
fn entry_and_depth_bounds_fail_closed() {
    let (_base, html) = tree();
    let few = Bounds {
        entries: 4,
        depth: 32,
    };
    assert!(census(&open(&html), me(), few).is_err());
    let shallow = Bounds {
        entries: 100,
        depth: 1,
    };
    assert!(census(&open(&html), me(), shallow).is_err());
    let exact = Bounds {
        entries: 5,
        depth: 2,
    };
    assert!(census(&open(&html), me(), exact).is_ok());
}

#[test]
fn directory_swapped_for_symlink_in_the_race_window_fails_closed() {
    let (base, html) = tree();
    let outside = base.path().join("outside");
    stdfs::create_dir(&outside).unwrap();
    stdfs::write(outside.join("secret"), "x").unwrap();
    let mut swapped = false;
    let result = census_with(&open(&html), me(), BOUNDS, &mut |_, name| {
        if name == "wp-includes" && !swapped {
            swapped = true;
            stdfs::rename(html.join("wp-includes"), base.path().join("moved")).unwrap();
            symlink(&outside, html.join("wp-includes")).unwrap();
        }
    });
    assert!(swapped);
    assert!(result.is_err());
}

#[test]
fn directory_swapped_for_another_directory_fails_closed() {
    let (base, html) = tree();
    let other = base.path().join("other");
    stdfs::create_dir_all(other.join("deep")).unwrap();
    let mut swapped = false;
    let result = census_with(&open(&html), me(), BOUNDS, &mut |_, name| {
        if name == "wp-includes" && !swapped {
            swapped = true;
            stdfs::rename(html.join("wp-includes"), base.path().join("moved")).unwrap();
            stdfs::rename(&other, html.join("wp-includes")).unwrap();
        }
    });
    assert!(swapped);
    assert!(result.is_err());
}

#[test]
fn concurrent_swapper_never_counts_outside_files() {
    let (base, html) = tree();
    let outside = base.path().join("outside");
    stdfs::create_dir(&outside).unwrap();
    for n in 0..50 {
        stdfs::write(outside.join(format!("{n}")), "x").unwrap();
    }
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (flag, dir, out, park) = (
        stop.clone(),
        html.clone(),
        outside.clone(),
        base.path().join("parked"),
    );
    let swapper = std::thread::spawn(move || {
        while !flag.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = stdfs::rename(dir.join("wp-includes"), &park);
            let _ = symlink(&out, dir.join("wp-includes"));
            let _ = stdfs::remove_file(dir.join("wp-includes"));
            let _ = stdfs::rename(&park, dir.join("wp-includes"));
        }
    });
    for _ in 0..2_000 {
        if let Ok(found) = census(&open(&html), me(), BOUNDS) {
            assert!(found.owned_files <= 3, "{found:?}");
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    swapper.join().unwrap();
}

const WANT: &[u8] = b"system_u:object_r:httpd_sys_content_t:s0:c42";

#[test]
fn labelled_census_counts_a_wrong_or_unreadable_label() {
    let (_base, html) = tree();
    let all = |_: &OwnedFd, _: &std::ffi::CStr| Some(WANT.to_vec());
    let got = census_labelled(&open(&html), me(), WANT, &all, BOUNDS).unwrap();
    assert_eq!((got.owned_files, got.foreign, got.mislabelled), (3, 0, 0));
    let one = |_: &OwnedFd, name: &std::ffi::CStr| {
        (name.to_bytes() != b"index.php")
            .then(|| WANT.to_vec())
            .or_else(|| Some(b"system_u:object_r:passwd_file_t:s0".to_vec()))
    };
    assert_eq!(
        census_labelled(&open(&html), me(), WANT, &one, BOUNDS)
            .unwrap()
            .mislabelled,
        1
    );
    let other_level = |_: &OwnedFd, name: &std::ffi::CStr| {
        Some(if name.to_bytes() == b"js" {
            b"system_u:object_r:httpd_sys_content_t:s0:c43".to_vec()
        } else {
            WANT.to_vec()
        })
    };
    assert_eq!(
        census_labelled(&open(&html), me(), WANT, &other_level, BOUNDS)
            .unwrap()
            .mislabelled,
        1
    );
    let unreadable = |_: &OwnedFd, name: &std::ffi::CStr| {
        (name.to_bytes() != b"wp-includes").then(|| WANT.to_vec())
    };
    assert_eq!(
        census_labelled(&open(&html), me(), WANT, &unreadable, BOUNDS)
            .unwrap()
            .mislabelled,
        1
    );
}

#[test]
fn live_label_reader_fails_closed_without_a_label() {
    // Test filesystems here carry no security.selinux (or another label):
    // every directory and regular file must count, never pass by default.
    let (_base, html) = tree();
    let got = census_labelled(&open(&html), me(), WANT, &label_of, BOUNDS).unwrap();
    assert_eq!(got.mislabelled, 5, "3 files + 2 directories");
}

/// A name that is valid on Linux but not UTF-8 (W328 c3e).
const NOT_UTF8: &[u8] = b"w328-\xff\xfe";

fn not_utf8(parent: &Path) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStrExt;
    parent.join(std::ffi::OsStr::from_bytes(NOT_UTF8))
}

#[test]
fn a_directory_with_a_non_utf8_name_is_walked() {
    let (_base, html) = tree();
    let dir = not_utf8(&html.join("wp-includes"));
    stdfs::create_dir(&dir).unwrap();
    stdfs::write(dir.join("a.txt"), "x").unwrap();
    let found = census(&open(&html), me(), BOUNDS).unwrap();
    assert_eq!((found.owned_files, found.foreign), (4, 0));
}

#[test]
fn the_label_reader_reads_an_attribute_of_a_non_utf8_name() {
    // W328 c3e: `label_of` returned None for a non-UTF-8 name, so a
    // correctly labelled restored file counted as mislabelled. The reader is
    // checked with a user attribute, because test hosts carry no SELinux label.
    let (_base, html) = tree();
    let file = not_utf8(&html);
    stdfs::write(&file, "x").unwrap();
    fs::setxattr(
        &file,
        "user.rustiron_census",
        b"want",
        fs::XattrFlags::empty(),
    )
    .unwrap();
    let name = std::ffi::CString::new(NOT_UTF8).unwrap();
    assert_eq!(
        read_attribute(&open(&html), &name, "user.rustiron_census").as_deref(),
        Some(&b"want"[..])
    );
}
