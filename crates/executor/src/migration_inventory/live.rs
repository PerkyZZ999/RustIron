//! D-066 (W478): what a real CyberPanel export holds besides the live site.
//!
//! A site's home often keeps an older copy and its database (for example
//! `public_html.old-<date>`), and CyberPanel adds a `mail.<hostname>` child
//! domain whose folder holds only its placeholder page. The import moves the
//! live site only: the database that the live `wp-config.php` names, and no
//! placeholder child domain. Anything else stays a refusal.

use rustix::{
    fd::OwnedFd,
    fs::{self, FileType, Mode},
};

use super::{open_regular, read_small, walk::DIRECTORY};

/// Largest `wp-config.php` read; a larger file names no database here.
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
/// Largest placeholder page of a `mail.<hostname>` child domain.
const MAX_PLACEHOLDER_BYTES: u64 = 64 * 1024;

/// A quoted PHP literal at the start of `text` with no escape inside, and the
/// text after it.
fn literal(text: &str) -> Option<(&str, &str)> {
    let quote = text.chars().next().filter(|c| *c == '\'' || *c == '"')?;
    let body = &text[1..];
    let end = body.find(quote)?;
    let value = &body[..end];
    (!value.contains('\\')).then(|| (value, &body[end + 1..]))
}

/// The one `define('DB_NAME', '<name>')` of a `wp-config.php` text. None when
/// there is none, more than one (even a commented-out one), or the value is
/// not a plain database name.
pub(crate) fn db_name(text: &str) -> Option<String> {
    let mut found: Option<String> = None;
    let mut rest = text;
    while let Some(at) = rest.find("define") {
        rest = &rest[at + "define".len()..];
        let Some(after) = rest.trim_start().strip_prefix('(') else {
            continue;
        };
        let Some((key, after)) = literal(after.trim_start()) else {
            continue;
        };
        if key != "DB_NAME" {
            continue;
        }
        let after = after.trim_start().strip_prefix(',')?;
        let (value, after) = literal(after.trim_start())?;
        after.trim_start().strip_prefix(')')?;
        let plain = (1..=64).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        if !plain || found.replace(value.to_owned()).is_some() {
            return None;
        }
    }
    found
}

/// The database that the live site's `wp-config.php` (`public_html/` of the
/// home tree) names, when it is one of the export's dumps.
pub(crate) fn live_database(home: &OwnedFd, databases: &[String]) -> Option<String> {
    let docroot = fs::openat(home, "public_html", DIRECTORY, Mode::empty()).ok()?;
    let bytes = read_small(&docroot, "wp-config.php", MAX_CONFIG_BYTES).ok()?;
    let name = db_name(std::str::from_utf8(&bytes).ok()?)?;
    databases.contains(&name).then_some(name)
}

/// D-074: whether the live document root holds a `wp-config.php` entry of
/// any type. An export without a database is static only when it does not.
pub(crate) fn has_wp_config(home: &OwnedFd) -> bool {
    let Ok(docroot) = fs::openat(home, "public_html", DIRECTORY, Mode::empty()) else {
        return true;
    };
    !matches!(
        fs::statat(&docroot, "wp-config.php", fs::AtFlags::SYMLINK_NOFOLLOW),
        Err(rustix::io::Errno::NOENT)
    )
}

/// True when `child` is `mail.<hostname>` and its folder in the home tree
/// holds only one small regular `index.html`.
pub(crate) fn placeholder_child(home: &OwnedFd, hostname: &str, child: &str) -> bool {
    if child != format!("mail.{hostname}") {
        return false;
    }
    let Ok(folder) = fs::openat(home, child, DIRECTORY, Mode::empty()) else {
        return false;
    };
    let Ok(listing) = fs::Dir::read_from(&folder) else {
        return false;
    };
    let mut names = Vec::new();
    for entry in listing {
        let Ok(entry) = entry else {
            return false;
        };
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    }
    if names != [b"index.html".to_vec()] {
        return false;
    }
    match open_regular(&folder, "index.html") {
        Ok(Some(page)) => fs::fstat(&page).is_ok_and(|stat| {
            FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                && u64::try_from(stat.st_size).is_ok_and(|size| size <= MAX_PLACEHOLDER_BYTES)
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_plain_db_name_is_read() {
        assert_eq!(
            db_name("<?php\ndefine( 'DB_NAME', 'assurcam_v2' );\ndefine('DB_USER', 'u');\n")
                .as_deref(),
            Some("assurcam_v2")
        );
        assert_eq!(
            db_name("define(\"DB_NAME\",\"blog\");").as_deref(),
            Some("blog")
        );
        for text in [
            "",
            "define('DB_USER', 'u');",
            // Two definitions, even if one is a comment: ambiguous.
            "// define('DB_NAME', 'old');\ndefine('DB_NAME', 'new');",
            // Not a literal.
            "define('DB_NAME', getenv('DB'));",
            "define('DB_NAME', 'a\\'b');",
            "define('DB_NAME', 'bad-name');",
            "define('DB_NAME', 'x'",
        ] {
            assert_eq!(db_name(text), None, "{text}");
        }
    }

    fn home() -> (tempfile_dir::Dir, OwnedFd) {
        let dir = tempfile_dir::Dir::new();
        let fd = fs::open(dir.path(), DIRECTORY, Mode::empty()).unwrap();
        (dir, fd)
    }

    mod tempfile_dir {
        pub(super) struct Dir(std::path::PathBuf);
        impl Dir {
            pub(super) fn new() -> Self {
                use std::sync::atomic::{AtomicUsize, Ordering};
                static NEXT: AtomicUsize = AtomicUsize::new(0);
                let path = std::env::temp_dir().join(format!(
                    "rustiron-live-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&path).unwrap();
                Self(path)
            }
            pub(super) fn path(&self) -> &std::path::Path {
                &self.0
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn the_live_database_comes_from_the_document_root_config() {
        let (dir, fd) = home();
        std::fs::create_dir(dir.path().join("public_html")).unwrap();
        std::fs::write(
            dir.path().join("public_html/wp-config.php"),
            "<?php define( 'DB_NAME', 'live_db' );",
        )
        .unwrap();
        let both = ["old_db".to_owned(), "live_db".to_owned()];
        assert_eq!(live_database(&fd, &both).as_deref(), Some("live_db"));
        assert_eq!(
            live_database(&fd, &["old_db".to_owned()]),
            None,
            "not a dump"
        );
    }

    #[test]
    fn only_a_placeholder_mail_child_is_left_behind() {
        let (dir, fd) = home();
        let child = dir.path().join("mail.example.test");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(child.join("index.html"), "<html>placeholder</html>").unwrap();
        assert!(placeholder_child(&fd, "example.test", "mail.example.test"));
        assert!(
            !placeholder_child(&fd, "example.test", "shop.example.test"),
            "not mail."
        );
        assert!(
            !placeholder_child(&fd, "other.test", "mail.example.test"),
            "other host"
        );
        std::fs::write(child.join("app.php"), "<?php").unwrap();
        assert!(
            !placeholder_child(&fd, "example.test", "mail.example.test"),
            "content"
        );
        std::fs::remove_file(child.join("app.php")).unwrap();
        std::fs::write(child.join("index.html"), vec![b'x'; 70 * 1024]).unwrap();
        assert!(
            !placeholder_child(&fd, "example.test", "mail.example.test"),
            "too large"
        );
        std::fs::remove_file(child.join("index.html")).unwrap();
        assert!(
            !placeholder_child(&fd, "example.test", "mail.example.test"),
            "empty"
        );
    }
}
