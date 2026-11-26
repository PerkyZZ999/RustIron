//! W384 (B08, B10): crash-safe staging of a content-addressed generation.
//! A partial or changed folder under the id is moved aside and staged
//! again; temporary folders of a crash are never read or deleted; a staging
//! never shows a folder under the id with only some of its files.

use super::stage::{prepare_owned, publish_owned};
use super::{
    Generation, QUARANTINE_MARK, STAGING_MARK, Staged, Staging, digest, generation_id,
    read_generation, stage_owned,
};
use crate::{ExecutorError, files};
use rustiron_contracts::Id;
use rustix::fd::OwnedFd;
use rustix::fs::{self, Mode, OFlags};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
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
    let path = std::env::temp_dir().join(format!("w384-{tag}-{}", std::process::id()));
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

fn me() -> u32 {
    rustix::process::getuid().as_raw()
}

/// A rendered-like generation of three files and its content-addressed id.
fn render(tag: &str) -> (Id, Generation) {
    let generation = Generation::from([
        (
            "vhosts.conf".to_owned(),
            format!("map {tag}\n").repeat(64).into_bytes(),
        ),
        (
            "rs_blog5.vhost".to_owned(),
            format!("vhost blog5 {tag}\n").into_bytes(),
        ),
        (
            "rs_blog6.vhost".to_owned(),
            format!("vhost blog6 {tag}\n").into_bytes(),
        ),
    ]);
    (generation_id(&digest(&generation)), generation)
}

fn stage(
    inc: &Include,
    target: &Id,
    generation: &Generation,
    operation: &str,
) -> Result<Staged, ExecutorError> {
    stage_owned(&inc.fd, target, generation, &id(operation), me())
}

fn folder(inc: &Include, name: &str) -> PathBuf {
    inc.path.join("generations").join(name)
}

/// The files under `generations/<name>`, as the executor reads them.
fn stored(inc: &Include, name: &str) -> Generation {
    let generations = files::open_child_directory(&inc.fd, "generations", me()).unwrap();
    let directory = files::open_child_directory(&generations, name, me()).unwrap();
    read_generation(&directory, me()).unwrap()
}

fn entries(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn temporaries(inc: &Include) -> Vec<String> {
    entries(&inc.path.join("generations"))
        .into_iter()
        .filter(|name| name.contains(STAGING_MARK))
        .collect()
}

/// A crash after the folder and two of its three files: the shape that a
/// staging before W384 could leave under the id.
fn plant_partial(inc: &Include, name: &str, generation: &Generation) {
    let path = folder(inc, name);
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut files = generation.iter();
    let (first, bytes) = files.next().unwrap();
    std::fs::write(path.join(first), &bytes[..bytes.len() / 2]).unwrap();
    let (second, _) = files.next().unwrap();
    std::fs::write(path.join(second), b"").unwrap();
    for entry in std::fs::read_dir(&path).unwrap() {
        std::fs::set_permissions(
            entry.unwrap().path(),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
    }
}

#[test]
fn a_new_generation_is_written_under_its_id_with_no_leftover() {
    let inc = include("normal");
    let (target, generation) = render("a");
    assert_eq!(
        stage(&inc, &target, &generation, "op_1"),
        Ok(Staged::Written)
    );
    assert_eq!(stored(&inc, target.as_str()), generation);
    assert_eq!(entries(&inc.path.join("generations")), [target.as_str()]);
    let path = folder(&inc, target.as_str());
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o7777, 0o755);
    for name in generation.keys() {
        assert_eq!(
            std::fs::metadata(path.join(name)).unwrap().mode() & 0o7777,
            0o644
        );
    }
}

#[test]
fn an_identical_folder_is_reused_and_nothing_is_written() {
    let inc = include("reuse");
    let (target, generation) = render("a");
    stage(&inc, &target, &generation, "op_1").unwrap();
    // OLS writes its own copies into a served folder (W372); they do not count.
    std::fs::write(folder(&inc, target.as_str()).join("vhosts.conf0"), b"copy").unwrap();
    let before = std::fs::metadata(folder(&inc, target.as_str()))
        .unwrap()
        .ino();
    assert_eq!(
        stage(&inc, &target, &generation, "op_2"),
        Ok(Staged::Reused)
    );
    assert_eq!(
        std::fs::metadata(folder(&inc, target.as_str()))
            .unwrap()
            .ino(),
        before
    );
    assert_eq!(entries(&inc.path.join("generations")), [target.as_str()]);
}

#[test]
fn a_partial_folder_is_quarantined_and_staged_again() {
    let inc = include("partial");
    let (target, generation) = render("a");
    plant_partial(&inc, target.as_str(), &generation);
    let partial = stored(&inc, target.as_str());
    // Before W384, every activation to this target failed here.
    assert_eq!(
        stage(&inc, &target, &generation, "op_2"),
        Ok(Staged::Quarantined(format!(
            "{}{QUARANTINE_MARK}op_2",
            target.as_str()
        )))
    );
    assert_eq!(stored(&inc, target.as_str()), generation);
    let kept = format!("{}{QUARANTINE_MARK}op_2", target.as_str());
    assert_eq!(
        stored(&inc, &kept),
        partial,
        "the partial folder is kept as it was"
    );
    assert_eq!(
        entries(&inc.path.join("generations")),
        [target.as_str().to_owned(), kept]
    );
    // The next activation to the same target reuses the new folder.
    assert_eq!(
        stage(&inc, &target, &generation, "op_3"),
        Ok(Staged::Reused)
    );
}

#[test]
fn a_wrong_digest_folder_is_quarantined_and_never_trusted() {
    let inc = include("wrong");
    let (target, generation) = render("a");
    let (_, other) = render("b");
    // All files present, other bytes, and one extra file.
    let path = folder(&inc, target.as_str());
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    for (name, bytes) in other
        .iter()
        .chain([(&"extra.conf".to_owned(), &b"x".to_vec())])
    {
        std::fs::write(path.join(name), bytes).unwrap();
        std::fs::set_permissions(path.join(name), std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let kept = format!("{}{QUARANTINE_MARK}op_7", target.as_str());
    assert_eq!(
        stage(&inc, &target, &generation, "op_7"),
        Ok(Staged::Quarantined(kept.clone()))
    );
    assert_eq!(stored(&inc, target.as_str()), generation);
    assert_eq!(stored(&inc, &kept).len(), 4);
}

#[test]
fn a_crash_before_the_rename_leaves_only_a_temporary_folder() {
    let inc = include("crash");
    let (target, generation) = render("a");
    // The crash point: the temporary folder is complete, the rename never ran.
    let staging = prepare_owned(&inc.fd, &target, &generation, &id("op_1"), me()).unwrap();
    let Staging::Ready {
        temporary,
        quarantined,
        ..
    } = &staging
    else {
        panic!("a new target needs a temporary folder");
    };
    assert_eq!(quarantined, &None);
    assert!(temporary.starts_with(&format!("{}{STAGING_MARK}", target.as_str())));
    assert!(
        !folder(&inc, target.as_str()).exists(),
        "nothing has the id"
    );
    assert_eq!(stored(&inc, temporary), generation);
    let leftover = temporary.clone();
    drop(staging);
    // The next activation to the same target stages a new folder and
    // leaves the leftover as it was.
    assert_eq!(
        stage(&inc, &target, &generation, "op_2"),
        Ok(Staged::Written)
    );
    assert_eq!(stored(&inc, target.as_str()), generation);
    assert_eq!(temporaries(&inc), std::slice::from_ref(&leftover));
    assert_eq!(stored(&inc, &leftover), generation);
}

#[test]
fn leftover_temporary_folders_are_never_read_or_deleted() {
    let inc = include("leftovers");
    let (target, generation) = render("a");
    let (other, _) = render("b");
    // Several crashes for this target and another one: a partial folder, an
    // empty one, one with a planted link, and one with a foreign mode.
    let outside = inc.path.join("outside");
    std::fs::create_dir(&outside).unwrap();
    let planted = [
        format!("{}{STAGING_MARK}00000000000000aa", target.as_str()),
        format!("{}{STAGING_MARK}00000000000000bb", target.as_str()),
        format!("{}{STAGING_MARK}00000000000000cc", target.as_str()),
        format!("{}{STAGING_MARK}00000000000000dd", other.as_str()),
        format!("{}{QUARANTINE_MARK}op_0", target.as_str()),
    ];
    plant_partial(&inc, &planted[0], &generation);
    std::fs::create_dir(folder(&inc, &planted[1])).unwrap();
    std::fs::create_dir(folder(&inc, &planted[2])).unwrap();
    symlink(&outside, folder(&inc, &planted[2]).join("vhosts.conf")).unwrap();
    std::fs::create_dir(folder(&inc, &planted[3])).unwrap();
    std::fs::set_permissions(
        folder(&inc, &planted[3]),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    plant_partial(&inc, &planted[4], &generation);
    assert_eq!(
        stage(&inc, &target, &generation, "op_1"),
        Ok(Staged::Written)
    );
    assert_eq!(stored(&inc, target.as_str()), generation);
    let mut expected: Vec<String> = planted.to_vec();
    expected.push(target.as_str().to_owned());
    expected.sort();
    assert_eq!(entries(&inc.path.join("generations")), expected);
    assert_eq!(entries(&folder(&inc, &planted[0])).len(), 2);
    assert!(folder(&inc, &planted[2]).join("vhosts.conf").is_symlink());
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    // The read-only listing names every leftover and no generation.
    let generations = files::open_child_directory(&inc.fd, "generations", me()).unwrap();
    assert_eq!(super::stage::leftovers_in(&generations).unwrap(), {
        let mut names = planted.to_vec();
        names.sort();
        names
    });
}

#[test]
fn a_second_quarantine_of_one_operation_is_refused() {
    let inc = include("requarantine");
    let (target, generation) = render("a");
    plant_partial(
        &inc,
        &format!("{}{QUARANTINE_MARK}op_1", target.as_str()),
        &generation,
    );
    plant_partial(&inc, target.as_str(), &generation);
    assert_eq!(
        stage(&inc, &target, &generation, "op_1"),
        Err(ExecutorError::Collision),
        "an existing quarantine name is never replaced"
    );
    assert_ne!(stored(&inc, target.as_str()), generation);
    assert!(temporaries(&inc).is_empty());
}

#[test]
fn a_foreign_entry_under_the_id_is_refused_and_left_alone() {
    let (target, generation) = render("a");
    let inc = include("file");
    std::fs::write(folder(&inc, target.as_str()), b"planted").unwrap();
    assert_eq!(
        stage(&inc, &target, &generation, "op_1"),
        Err(ExecutorError::Collision)
    );
    assert!(folder(&inc, target.as_str()).is_file());

    let inc = include("writable");
    plant_partial(&inc, target.as_str(), &generation);
    std::fs::set_permissions(
        folder(&inc, target.as_str()),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert_eq!(
        stage(&inc, &target, &generation, "op_1"),
        Err(ExecutorError::Collision)
    );

    let inc = include("linked");
    plant_partial(&inc, target.as_str(), &generation);
    let outside = inc.path.join("outside.conf");
    std::fs::write(&outside, b"outside").unwrap();
    symlink(&outside, folder(&inc, target.as_str()).join("planted.conf")).unwrap();
    assert_eq!(
        stage(&inc, &target, &generation, "op_1"),
        Err(ExecutorError::Collision)
    );
    assert_eq!(entries(&inc.path.join("generations")), [target.as_str()]);
    assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
}

#[test]
fn concurrent_stagings_of_one_target_never_show_a_partial_folder() {
    let inc = std::sync::Arc::new(include("concurrent"));
    let (target, generation) = render("a");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = {
        let (inc, stop, target, generation) = (
            inc.clone(),
            stop.clone(),
            target.clone(),
            generation.clone(),
        );
        std::thread::spawn(move || {
            let mut seen = 0_u32;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if folder(&inc, target.as_str()).exists() {
                    assert_eq!(stored(&inc, target.as_str()), generation, "partial folder");
                    seen += 1;
                }
            }
            seen
        })
    };
    let writers: Vec<_> = (0..8)
        .map(|n| {
            let (inc, target, generation) = (inc.clone(), target.clone(), generation.clone());
            std::thread::spawn(move || stage(&inc, &target, &generation, &format!("op_{n}")))
        })
        .collect();
    let results: Vec<_> = writers.into_iter().map(|w| w.join().unwrap()).collect();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = reader.join().unwrap();
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Ok(Staged::Written))
            .count(),
        1,
        "{results:?}"
    );
    for result in &results {
        assert!(
            matches!(
                result,
                Ok(Staged::Written | Staged::Reused) | Err(ExecutorError::Collision)
            ),
            "{result:?}"
        );
    }
    assert_eq!(stored(&inc, target.as_str()), generation);
    // A loser keeps its own complete temporary folder; nothing is deleted.
    let losers = results.iter().filter(|r| r.is_err()).count();
    assert_eq!(temporaries(&inc).len(), losers);
    // Publishing a temporary folder over the id is refused.
    let (other, _) = render("b");
    let staging = prepare_owned(&inc.fd, &other, &generation, &id("op_9"), me()).unwrap();
    std::fs::create_dir(folder(&inc, other.as_str())).unwrap();
    assert_eq!(
        publish_owned(&inc.fd, &other, staging, me()),
        Err(ExecutorError::Collision)
    );
}

/// W394 (B06): a link planted at the quarantine name is never followed or
/// replaced; the folder under the id stays where it was.
#[test]
fn w394_a_linked_quarantine_name_is_refused_and_never_followed() {
    let inc = include("w394-quarantine-link");
    let (target, generation) = render("a");
    let outside = inc.path.join("outside");
    std::fs::create_dir(&outside).unwrap();
    let name = format!("{}{QUARANTINE_MARK}op_1", target.as_str());
    symlink(&outside, folder(&inc, &name)).unwrap();
    plant_partial(&inc, target.as_str(), &generation);
    assert_eq!(
        stage(&inc, &target, &generation, "op_1"),
        Err(ExecutorError::Collision)
    );
    assert!(folder(&inc, &name).is_symlink());
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    assert_eq!(entries(&folder(&inc, target.as_str())).len(), 2);
    assert!(temporaries(&inc).is_empty());
}

/// Replaces the verified temporary folder of `staging` with `swap`, the
/// shape of a swap between the read-back and the rename.
fn swap_temporary(inc: &Include, staging: &Staging, swap: impl FnOnce(&Path)) -> PathBuf {
    let Staging::Ready { temporary, .. } = staging else {
        panic!("a new target needs a temporary folder");
    };
    let path = folder(inc, temporary);
    let aside = inc.path.join("verified-aside");
    std::fs::rename(&path, &aside).unwrap();
    swap(&path);
    aside
}

/// W394 (B06): a temporary folder swapped after its read-back, for a link
/// to a folder with the same files or for another folder with the same
/// files, is never published under the id. The swapped entry and the
/// outside folder stay as they were.
#[test]
fn w394_a_temporary_folder_swapped_before_the_rename_is_never_published() {
    let (target, generation) = render("a");

    let inc = include("w394-swap-link");
    let outside = inc.path.join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).unwrap();
    for (name, bytes) in &generation {
        std::fs::write(outside.join(name), bytes).unwrap();
    }
    let staging = prepare_owned(&inc.fd, &target, &generation, &id("op_1"), me()).unwrap();
    let aside = swap_temporary(&inc, &staging, |path| symlink(&outside, path).unwrap());
    assert_eq!(
        publish_owned(&inc.fd, &target, staging, me()),
        Err(ExecutorError::Collision),
        "a linked temporary folder was published"
    );
    assert!(
        std::fs::symlink_metadata(folder(&inc, target.as_str())).is_err(),
        "something has the id"
    );
    assert_eq!(entries(&outside).len(), generation.len());
    assert!(aside.is_dir());

    let inc = include("w394-swap-folder");
    let staging = prepare_owned(&inc.fd, &target, &generation, &id("op_1"), me()).unwrap();
    swap_temporary(&inc, &staging, |path| {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        for (name, bytes) in &generation {
            std::fs::write(path.join(name), bytes).unwrap();
            std::fs::set_permissions(path.join(name), std::fs::Permissions::from_mode(0o644))
                .unwrap();
        }
    });
    assert_eq!(
        publish_owned(&inc.fd, &target, staging, me()),
        Err(ExecutorError::Collision),
        "an unverified folder was published"
    );
    assert!(std::fs::symlink_metadata(folder(&inc, target.as_str())).is_err());
}
