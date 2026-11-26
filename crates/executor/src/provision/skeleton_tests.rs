use std::{cell::RefCell, collections::HashMap, os::unix::fs::MetadataExt, path::PathBuf};

use super::*;

struct Tree(PathBuf);

impl Tree {
    /// The skeleton step 2 creates (owners and modes do not matter here).
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rustiron-w274-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for skeleton_dir in SITE {
            std::fs::create_dir_all(dir.join(skeleton_dir.name)).unwrap();
        }
        std::fs::write(dir.join("errors/503.html"), b"page").unwrap();
        Self(dir)
    }

    fn open(&self) -> OwnedFd {
        fs::open(&self.0, DIRECTORY, Mode::empty()).unwrap()
    }

    fn ino(&self, name: &str) -> u64 {
        std::fs::symlink_metadata(self.0.join(name)).unwrap().ino()
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_exact_skeleton_opens_with_its_types() {
    let tree = Tree::new("ok");
    let entries = open_skeleton(&tree.open(), SITE).unwrap();
    let got: Vec<(u64, &str)> = entries
        .iter()
        .map(|e| (fs::fstat(&e.fd).unwrap().st_ino, e.kind))
        .collect();
    let want: Vec<(u64, &str)> = [
        ("errors/503.html", CONTENT),
        ("errors", CONTENT),
        ("html", CONTENT),
        ("logs", READ_WRITE),
        ("private", CONTENT),
        ("tmp", READ_WRITE),
    ]
    .into_iter()
    .map(|(name, kind)| (tree.ino(name), kind))
    .collect();
    assert_eq!(got, want);
}

#[test]
fn anything_beyond_the_skeleton_is_refused() {
    type Change = fn(&std::path::Path);
    let cases: [(&str, Change); 12] = [
        ("extra-root-entry", |d| {
            std::fs::write(d.join("x"), b"").unwrap()
        }),
        ("missing-dir", |d| {
            std::fs::remove_dir(d.join("logs")).unwrap()
        }),
        ("file-in-html", |d| {
            std::fs::write(d.join("html/index.php"), b"").unwrap();
        }),
        ("dir-in-private", |d| {
            std::fs::create_dir(d.join("private/x")).unwrap();
        }),
        ("extra-error-file", |d| {
            std::fs::write(d.join("errors/404.html"), b"").unwrap();
        }),
        ("missing-page", |d| {
            std::fs::remove_file(d.join("errors/503.html")).unwrap();
        }),
        ("tmp-symlink", |d| {
            std::fs::remove_dir(d.join("tmp")).unwrap();
            std::os::unix::fs::symlink("/", d.join("tmp")).unwrap();
        }),
        ("html-is-a-file", |d| {
            std::fs::remove_dir(d.join("html")).unwrap();
            std::fs::write(d.join("html"), b"").unwrap();
        }),
        ("page-symlink", |d| {
            std::fs::remove_file(d.join("errors/503.html")).unwrap();
            std::os::unix::fs::symlink("/etc/passwd", d.join("errors/503.html")).unwrap();
        }),
        ("page-hard-link", |d| {
            // A second name outside the tree: same names inside, nlink 2.
            std::fs::hard_link(d.join("errors/503.html"), d.with_extension("link")).unwrap();
        }),
        ("page-fifo", |d| {
            // Opened non-blocking, so the type check refuses it at once.
            std::fs::remove_file(d.join("errors/503.html")).unwrap();
            let made = std::process::Command::new("mkfifo")
                .arg(d.join("errors/503.html"))
                .status()
                .unwrap();
            assert!(made.success());
        }),
        ("page-is-a-dir", |d| {
            std::fs::remove_file(d.join("errors/503.html")).unwrap();
            std::fs::create_dir(d.join("errors/503.html")).unwrap();
        }),
    ];
    for (tag, change) in cases {
        let tree = Tree::new(tag);
        change(&tree.0);
        let refused = open_skeleton(&tree.open(), SITE).err();
        let _ = std::fs::remove_file(tree.0.with_extension("link"));
        assert_eq!(refused, Some(ExecutorError::StepFailed), "{tag}");
    }
}

/// Fake label store keyed by inode, standing in for `security.selinux`.
#[derive(Default)]
struct Labels(RefCell<HashMap<u64, Vec<u8>>>);

impl Labels {
    fn set(&self, fd: &OwnedFd, label: &[u8]) -> Result<(), ExecutorError> {
        let ino = fs::fstat(fd).unwrap().st_ino;
        self.0.borrow_mut().insert(ino, label.to_vec());
        Ok(())
    }

    fn get(&self, fd: &OwnedFd) -> Option<Vec<u8>> {
        self.0.borrow().get(&fs::fstat(fd).unwrap().st_ino).cloned()
    }
}

#[test]
fn every_entry_gets_its_fcontext_label_through_its_descriptor() {
    let tree = Tree::new("label");
    let root = tree.open();
    let entries = open_skeleton(&root, SITE).unwrap();
    let labels = Labels::default();
    label_skeleton(
        &root,
        &entries,
        "s0:c42",
        &|fd, l| labels.set(fd, l),
        &|fd| labels.get(fd),
    )
    .unwrap();
    let store = labels.0.borrow();
    let at = |name: &str| String::from_utf8(store[&tree.ino(name)].clone()).unwrap();
    assert_eq!(at("."), "system_u:object_r:httpd_sys_content_t:s0:c42");
    for name in ["errors", "errors/503.html", "html", "private"] {
        assert_eq!(
            at(name),
            "system_u:object_r:httpd_sys_content_t:s0:c42",
            "{name}"
        );
    }
    for name in ["tmp", "logs"] {
        assert_eq!(
            at(name),
            "system_u:object_r:httpd_sys_rw_content_t:s0:c42",
            "{name}"
        );
    }
    assert_eq!(store.len(), 7, "root plus six entries, nothing else");
}

#[test]
fn a_failed_write_or_a_different_read_back_fails_the_step() {
    let tree = Tree::new("bad");
    let root = tree.open();
    let entries = open_skeleton(&root, SITE).unwrap();
    let refused = |_: &OwnedFd, _: &[u8]| Err(ExecutorError::StepFailed);
    assert_eq!(
        label_skeleton(&root, &entries, "s0:c1", &refused, &|_| None),
        Err(ExecutorError::StepFailed)
    );
    let labels = Labels::default();
    // The kernel kept another level (an MCS refusal would surface here).
    let other = |fd: &OwnedFd| {
        labels.get(fd).map(|l| {
            String::from_utf8(l)
                .unwrap()
                .replace(":s0:c1", ":s0")
                .into_bytes()
        })
    };
    assert_eq!(
        label_skeleton(&root, &entries, "s0:c1", &|fd, l| labels.set(fd, l), &other),
        Err(ExecutorError::StepFailed)
    );
    // An unreadable label is a failure, never a pass.
    assert_eq!(
        label_skeleton(
            &root,
            &entries,
            "s0:c1",
            &|fd, l| labels.set(fd, l),
            &|_| None
        ),
        Err(ExecutorError::StepFailed)
    );
}

/// W275: a restore probe's sandbox before any content is an empty `tmp/`.
#[test]
fn the_probe_sandbox_is_an_empty_tmp_labelled_read_write() {
    let probe = |tag: &str| {
        let tree =
            Tree(std::env::temp_dir().join(format!("rustiron-w275-{tag}-{}", std::process::id())));
        let _ = std::fs::remove_dir_all(&tree.0);
        std::fs::create_dir_all(tree.0.join("tmp")).unwrap();
        tree
    };
    let tree = probe("ok");
    let root = tree.open();
    let entries = open_skeleton(&root, PROBE).unwrap();
    let labels = Labels::default();
    label_skeleton(
        &root,
        &entries,
        "s0:c950",
        &|fd, l| labels.set(fd, l),
        &|fd| labels.get(fd),
    )
    .unwrap();
    let store = labels.0.borrow();
    let at = |name: &str| String::from_utf8(store[&tree.ino(name)].clone()).unwrap();
    assert_eq!(at("."), "system_u:object_r:httpd_sys_content_t:s0:c950");
    assert_eq!(
        at("tmp"),
        "system_u:object_r:httpd_sys_rw_content_t:s0:c950"
    );
    assert_eq!(store.len(), 2);

    type Change = fn(&std::path::Path);
    let cases: [(&str, Change); 5] = [
        ("content-in-tmp", |d| {
            std::fs::write(d.join("tmp/restore"), b"").unwrap();
        }),
        ("extra-root-entry", |d| {
            std::fs::create_dir(d.join("html")).unwrap();
        }),
        ("site-layout", |d| {
            for name in ["errors", "html", "logs", "private"] {
                std::fs::create_dir(d.join(name)).unwrap();
            }
        }),
        ("tmp-symlink", |d| {
            std::fs::remove_dir(d.join("tmp")).unwrap();
            std::os::unix::fs::symlink("/", d.join("tmp")).unwrap();
        }),
        ("no-tmp", |d| {
            std::fs::remove_dir(d.join("tmp")).unwrap();
        }),
    ];
    for (tag, change) in cases {
        let tree = probe(tag);
        change(&tree.0);
        assert_eq!(
            open_skeleton(&tree.open(), PROBE).err(),
            Some(ExecutorError::StepFailed),
            "{tag}"
        );
    }
    // The site layout is not a probe sandbox, and the reverse.
    let site = Tree::new("not-probe");
    assert!(open_skeleton(&site.open(), PROBE).is_err());
    assert!(open_skeleton(&tree.open(), SITE).is_err());
}

/// W277: the tree is checked again after labelling; an entry added in the
/// fcontext window, or an entry replaced by another object, fails the step.
#[test]
fn a_change_after_labelling_fails_the_recheck() {
    let tree = Tree::new("recheck-ok");
    let root = tree.open();
    let entries = open_skeleton(&root, SITE).unwrap();
    assert_eq!(unchanged(&root, SITE, &entries), Ok(()));

    let added = Tree::new("recheck-added");
    let root = added.open();
    let entries = open_skeleton(&root, SITE).unwrap();
    std::fs::write(added.0.join("tmp/late"), b"").unwrap();
    assert_eq!(
        unchanged(&root, SITE, &entries),
        Err(ExecutorError::StepFailed)
    );

    let replaced = Tree::new("recheck-replaced");
    let root = replaced.open();
    let entries = open_skeleton(&root, SITE).unwrap();
    std::fs::remove_dir(replaced.0.join("logs")).unwrap();
    std::fs::create_dir(replaced.0.join("logs")).unwrap();
    assert_eq!(
        unchanged(&root, SITE, &entries),
        Err(ExecutorError::StepFailed)
    );
}
