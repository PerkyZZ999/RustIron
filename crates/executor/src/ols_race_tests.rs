//! W242 (B08 include races): staging and switching against planted
//! entries, and readers never seeing a partial `current` during switches.

use super::{Generation, Staged, stage_owned, switch};
use rustiron_contracts::Id;
use rustix::fd::OwnedFd;
use rustix::fs::{self, Mode, OFlags};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

struct Include {
    path: PathBuf,
    fd: OwnedFd,
}

impl Drop for Include {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn include(tag: &str) -> Include {
    let path = std::env::temp_dir().join(format!("w242-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(path.join("generations")).unwrap();
    for dir in [path.clone(), path.join("generations")] {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let fd = fs::open(&path, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
    Include { path, fd }
}

fn id(text: &str) -> Id {
    Id::try_from(text.to_owned()).unwrap()
}

fn generation(body: &str) -> Generation {
    Generation::from([("site.conf".to_owned(), body.as_bytes().to_vec())])
}

fn me() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Stages `generation` under `name` as the test user for operation `op_w242`.
fn stage(
    inc: &Include,
    name: &str,
    generation: &Generation,
) -> Result<Staged, crate::ExecutorError> {
    stage_owned(&inc.fd, &id(name), generation, &id("op_w242"), me())
}

fn leftovers(path: &Path) -> Vec<String> {
    std::fs::read_dir(path)
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.starts_with("current.next-"))
        .collect()
}

#[test]
fn stage_refuses_a_planted_generation() {
    let inc = include("collide");
    // A planted symlink under the id is never followed, written through,
    // or moved aside (W384 moves only a root-owned folder aside).
    let outside = inc.path.join("outside");
    std::fs::create_dir(&outside).unwrap();
    symlink(&outside, inc.path.join("generations/gb")).unwrap();
    assert_eq!(
        stage(&inc, "gb", &generation("b")),
        Err(crate::ExecutorError::Collision)
    );
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    assert!(inc.path.join("generations/gb").is_symlink());
}

#[test]
fn stage_refuses_a_redirected_or_writable_generations_dir() {
    let inc = include("redirect");
    let elsewhere = inc.path.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_dir(inc.path.join("generations")).unwrap();
    symlink(&elsewhere, inc.path.join("generations")).unwrap();
    assert!(stage(&inc, "ga", &generation("a")).is_err());
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);

    let inc = include("writable");
    std::fs::set_permissions(
        inc.path.join("generations"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(stage(&inc, "ga", &generation("a")).is_err());
    assert!(!inc.path.join("generations/ga").exists());
}

#[test]
fn switch_onto_a_planted_directory_fails_and_cleans_up() {
    let inc = include("planted");
    stage(&inc, "ga", &generation("a")).unwrap();
    std::fs::create_dir(inc.path.join("current")).unwrap();
    std::fs::write(inc.path.join("current/keep"), b"k").unwrap();
    assert!(switch(&inc.fd, &id("ga")).is_err());
    assert_eq!(std::fs::read(inc.path.join("current/keep")).unwrap(), b"k");
    assert!(leftovers(&inc.path).is_empty());
}

#[test]
fn readers_see_a_whole_generation_through_every_switch() {
    let inc = include("readers");
    let a = "A".repeat(64 * 1024);
    let b = "B".repeat(64 * 1024);
    stage(&inc, "ga", &generation(&a)).unwrap();
    stage(&inc, "gb", &generation(&b)).unwrap();
    switch(&inc.fd, &id("ga")).unwrap();
    let file = inc.path.join("current/site.conf");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let (file, stop, a, b) = (file.clone(), stop.clone(), a.clone(), b.clone());
            std::thread::spawn(move || {
                let mut reads = 0_u32;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let seen = std::fs::read_to_string(&file).expect("current always resolves");
                    assert!(seen == a || seen == b, "partial or mixed generation");
                    reads += 1;
                }
                reads
            })
        })
        .collect();
    for round in 0..500 {
        let target = if round % 2 == 0 { "gb" } else { "ga" };
        switch(&inc.fd, &id(target)).unwrap();
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let reads: u32 = readers.into_iter().map(|r| r.join().unwrap()).sum();
    assert!(reads > 0);
    assert!(leftovers(&inc.path).is_empty());
    assert_eq!(
        std::fs::read_link(inc.path.join("current")).unwrap(),
        Path::new("generations/ga")
    );
}
