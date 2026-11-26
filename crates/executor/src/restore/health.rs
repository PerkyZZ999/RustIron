//! D-034 (W383): the probe health check, judged outside the restored code.
//!
//! W378 f4: restored code ran in the same PHP process as the old health
//! script and wrote a healthy report for a database without its admin user.
//! Now two units run, and root judges their output:
//!
//! 1. **Facts.** Right after the import, before any restored PHP runs, the
//!    fixed `mariadb` client reads the restored database with fixed SQL as
//!    the probe account in `rustiron_capture_t`. It runs no restored code.
//! 2. **Render.** The restored WordPress renders its home page in
//!    `rustiron_php_t`. The page is the unit's only output.
//!
//! PID 1 writes each unit's stdout to a root-owned file in the helper's
//! runtime directory, outside the sandbox. `LimitFSIZE=` bounds the file.
//! The restored tree cannot write either file except through the render's
//! own stdout, which is the page. The database facts decide the database
//! fields; restored code controls only the page.

/// The WordPress tables the facts read (the provisioned `wp_` prefix).
const TABLES: u64 = 3;
/// Fixed SQL of the facts reader: four counts on one line. The three tables
/// must be base tables, not views. A missing table is an SQL error, so the
/// reader fails and the facts are unknown.
pub(super) const FACTS_SQL: &str = "SELECT (SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('wp_options','wp_users','wp_posts') AND TABLE_TYPE='BASE TABLE'), (SELECT COUNT(*) FROM wp_options WHERE option_name='siteurl' AND option_value<>''), (SELECT COUNT(*) FROM wp_users WHERE user_login='rustiron_admin'), (SELECT COUNT(*) FROM wp_posts WHERE post_type='post' AND post_status='publish')";
/// Bound on the facts line (four decimal counts and separators).
pub(super) const MAX_FACTS_BYTES: usize = 128;
/// Bound on the rendered page. The render unit's `LimitFSIZE=` stops the
/// page write at this size, so root never reads a larger file.
pub(super) const MAX_PAGE_BYTES: usize = 1 << 20;
/// Bound on the reported title, in characters.
const MAX_TITLE_CHARS: usize = 200;

/// Counts the facts reader printed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Facts {
    tables: u64,
    siteurl: u64,
    admin: u64,
    posts: u64,
}

/// The rendered page as root reads it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Render {
    bytes: u64,
    title: Option<String>,
}

/// The facts reader's `mariadb` argv. The client options precede the
/// statement: no client file or shell commands, no local file reads.
pub(super) fn facts_argv(bin: &str, site: &str, probe: &str) -> Vec<String> {
    vec![
        format!("{bin}/mariadb"),
        format!("--defaults-file={site}/private/db.cnf"),
        "--sandbox".to_owned(),
        "--local-infile=0".to_owned(),
        "--batch".to_owned(),
        "--skip-column-names".to_owned(),
        format!("--execute={FACTS_SQL}"),
        probe.to_owned(),
    ]
}

/// One line of four canonical decimal counts separated by tabs.
pub(super) fn parse_facts(bytes: &[u8]) -> Option<Facts> {
    if bytes.len() > MAX_FACTS_BYTES {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let line = text.strip_suffix('\n')?;
    let counts: Vec<u64> = line
        .split('\t')
        .map(|count| {
            let canonical = !count.is_empty()
                && count.bytes().all(|byte| byte.is_ascii_digit())
                && (count == "0" || !count.starts_with('0'));
            canonical.then(|| count.parse().ok()).flatten()
        })
        .collect::<Option<_>>()?;
    match counts[..] {
        [tables, siteurl, admin, posts] => Some(Facts {
            tables,
            siteurl,
            admin,
            posts,
        }),
        _ => None,
    }
}

/// The page size and the text of its first `<title>` element.
pub(super) fn parse_render(page: &[u8]) -> Render {
    let text = String::from_utf8_lossy(page);
    let lower = text.to_ascii_lowercase();
    let title = lower.find("<title").and_then(|open| {
        let start = open + lower[open..].find('>')? + 1;
        let end = start + lower[start..].find("</title")?;
        let title: String = text[start..end]
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(MAX_TITLE_CHARS)
            .collect();
        let title = title.trim();
        (!title.is_empty()).then(|| title.to_owned())
    });
    Render {
        bytes: page.len() as u64,
        title,
    }
}

/// Runs the facts reader, then the render, in that order: the facts are
/// read before any restored PHP can change the database. Returns the
/// observation that the receipt records.
pub(super) fn judge(
    facts: impl FnOnce() -> Option<Facts>,
    render: impl FnOnce() -> Option<Render>,
) -> serde_json::Value {
    let facts = facts();
    let render = facts.and_then(|_| render());
    observation(facts.as_ref(), render.as_ref())
}

/// The receipt's `observed` member. The database fields come only from the
/// facts reader; the page fields come only from the render.
fn observation(facts: Option<&Facts>, render: Option<&Render>) -> serde_json::Value {
    serde_json::json!({
        "source": "database: fixed SQL by a reader that runs no restored code, before the restored PHP ran; page: the restored PHP's own output",
        "installed": facts.is_some_and(|f| f.tables == TABLES && f.siteurl == 1),
        "admin_exists": facts.is_some_and(|f| f.admin == 1),
        "published_posts": facts.map(|f| f.posts),
        "home_bytes": render.map(|r| r.bytes),
        "home_title": render.and_then(|r| r.title.clone()),
    })
}

/// Whether an observation passes: WordPress installed, the admin user
/// present, and a titled home page.
pub(super) fn healthy(observed: &serde_json::Value) -> bool {
    observed["installed"] == true
        && observed["admin_exists"] == true
        && observed["home_title"]
            .as_str()
            .is_some_and(|title| !title.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(line: &str) -> Option<Facts> {
        parse_facts(line.as_bytes())
    }

    const PAGE: &str =
        "<!DOCTYPE html><html><head><TITLE>W383 Probe Site</TITLE></head><body>x</body></html>";

    #[test]
    fn the_facts_reader_runs_fixed_sql_with_no_client_shell_or_files() {
        let argv = facts_argv(
            "/usr/libexec/rustiron/jobs",
            "/r/srv/sites/rs_x",
            "rp_0a9fbc",
        );
        assert_eq!(argv[0], "/usr/libexec/rustiron/jobs/mariadb");
        assert_eq!(argv[1], "--defaults-file=/r/srv/sites/rs_x/private/db.cnf");
        let execute = argv
            .iter()
            .position(|a| a.starts_with("--execute="))
            .unwrap();
        for option in ["--sandbox", "--local-infile=0", "--batch"] {
            let at = argv.iter().position(|a| a == option).unwrap();
            assert!(at < execute, "{option} precedes the statement");
        }
        assert_eq!(argv[execute], format!("--execute={FACTS_SQL}"));
        assert_eq!(argv.last().map(String::as_str), Some("rp_0a9fbc"));
        // Only fixed text: no source, shell, file, or write statement.
        let sql = FACTS_SQL.to_ascii_lowercase();
        for word in [
            "source", "system", "\\!", "outfile", "load", "insert", "update", "delete", "call",
            "set ",
        ] {
            assert!(!sql.contains(word), "{word}");
        }
        assert!(sql.contains("table_type='base table'"));
    }

    #[test]
    fn only_one_line_of_four_canonical_counts_is_facts() {
        assert_eq!(
            facts("3\t1\t1\t41\n"),
            Some(Facts {
                tables: 3,
                siteurl: 1,
                admin: 1,
                posts: 41
            })
        );
        assert_eq!(facts("0\t0\t0\t0\n").map(|f| f.posts), Some(0));
        for bad in [
            "",
            "3\t1\t1\t41",
            "3\t1\t1\n",
            "3\t1\t1\t41\t5\n",
            "3\t1\t1\t41\n\n",
            "03\t1\t1\t41\n",
            "-3\t1\t1\t41\n",
            "3 1 1 41\n",
            "3\t1\t1\tNULL\n",
            "3\t1\t1\t99999999999999999999999\n",
            "3\t\t1\t41\n",
        ] {
            assert_eq!(facts(bad), None, "{bad:?}");
        }
        assert_eq!(parse_facts(&[b'1'; MAX_FACTS_BYTES + 1]), None);
    }

    #[test]
    fn the_title_comes_from_the_rendered_page() {
        let render = parse_render(PAGE.as_bytes());
        assert_eq!(render.title.as_deref(), Some("W383 Probe Site"));
        assert_eq!(render.bytes, PAGE.len() as u64);
        let escaped = parse_render(b"<title id=x>\x1b[31m bad\nname </title>");
        assert_eq!(escaped.title.as_deref(), Some("[31m bad name"));
        for page in [
            &b""[..],
            b"<title></title>",
            b"<title>  </title>",
            b"<title>open",
            b"no title",
        ] {
            assert_eq!(parse_render(page).title, None);
        }
        let long = format!("<title>{}</title>", "t".repeat(5000));
        assert_eq!(
            parse_render(long.as_bytes()).title.unwrap().len(),
            MAX_TITLE_CHARS
        );
    }

    #[test]
    fn a_forged_page_cannot_hide_a_missing_admin() {
        // W378 f4: the dump deleted the admin user and the restored plugin
        // reported a healthy site. The facts decide the database fields.
        let observed = judge(
            || facts("3\t1\t0\t999\n"),
            || Some(parse_render(PAGE.as_bytes())),
        );
        assert_eq!(observed["admin_exists"], false);
        assert_eq!(observed["home_title"], "W383 Probe Site");
        assert!(!healthy(&observed));
    }

    #[test]
    fn a_healthy_site_needs_every_fact_and_a_titled_page() {
        let page = || Some(parse_render(PAGE.as_bytes()));
        assert!(healthy(&judge(|| facts("3\t1\t1\t41\n"), page)));
        for line in [
            "2\t1\t1\t41\n",
            "3\t0\t1\t41\n",
            "3\t2\t1\t41\n",
            "3\t1\t2\t41\n",
        ] {
            assert!(!healthy(&judge(|| facts(line), page)), "{line:?}");
        }
        assert!(!healthy(&judge(|| None, page)));
        assert!(!healthy(&judge(|| facts("3\t1\t1\t41\n"), || None)));
        assert!(!healthy(&judge(
            || facts("3\t1\t1\t41\n"),
            || Some(parse_render(b"<html>no title</html>"))
        )));
    }

    #[test]
    fn the_facts_are_read_before_the_restored_php_runs() {
        let order = std::cell::RefCell::new(Vec::new());
        judge(
            || {
                order.borrow_mut().push("facts");
                facts("3\t1\t1\t41\n")
            },
            || {
                order.borrow_mut().push("render");
                None
            },
        );
        assert_eq!(*order.borrow(), ["facts", "render"]);
        // Unknown facts: the restored PHP never runs.
        let ran = std::cell::Cell::new(false);
        let observed = judge(
            || None,
            || {
                ran.set(true);
                None
            },
        );
        assert!(!ran.get());
        assert_eq!(observed["published_posts"], serde_json::Value::Null);
    }

    /// W394 (B06): a forged health report. The restored code controls only
    /// the page; a page that carries a facts line, a healthy JSON report, or
    /// a title cannot set a database field, and with unknown facts the
    /// restored PHP never runs.
    #[test]
    fn w394_restored_code_cannot_supply_the_database_facts() {
        let forged = concat!(
            "<title>W383 Probe Site</title>3\t1\t1\t41\n",
            r#"{"installed":true,"admin_exists":true,"published_posts":41}"#
        );
        let page = || Some(parse_render(forged.as_bytes()));
        let missing_admin = judge(|| facts("3\t1\t0\t41\n"), page);
        assert_eq!(missing_admin["admin_exists"], false);
        assert_eq!(missing_admin["published_posts"], 41);
        assert!(!healthy(&missing_admin));
        let no_tables = judge(|| facts("2\t1\t1\t41\n"), page);
        assert_eq!(no_tables["installed"], false);
        assert!(!healthy(&no_tables));
        let ran = std::cell::Cell::new(false);
        let unknown = judge(
            || parse_facts(forged.as_bytes()),
            || {
                ran.set(true);
                page()
            },
        );
        assert!(!ran.get(), "the page ran without facts");
        assert!(!healthy(&unknown));
        assert_eq!(unknown["installed"], false);
        assert_eq!(unknown["home_title"], serde_json::Value::Null);
    }
}
