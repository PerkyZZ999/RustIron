//! W704: every executor error code has a row in the error-code list, and the
//! list has no row for a code that does not exist.

use rustiron_executor::ExecutorError;

const LIST: &str = include_str!("../../../docs/technical/ERROR-CODES.md");

/// The codes in the table rows of one `## ` section of the list.
fn section_codes(heading: &str) -> Vec<&'static str> {
    let start = LIST.find(heading).expect("section heading");
    let section = &LIST[start + heading.len()..];
    let section = &section[..section.find("\n## ").unwrap_or(section.len())];
    section
        .lines()
        .filter_map(|line| line.strip_prefix("| `")?.split_once("` |"))
        .map(|(code, _)| code)
        .collect()
}

#[test]
fn every_executor_code_has_one_row_and_no_row_is_unknown() {
    let mut listed = section_codes("## Executor (`ExecutorError`)");
    let mut codes: Vec<&str> = ExecutorError::ALL.iter().map(|e| e.code()).collect();
    listed.sort_unstable();
    codes.sort_unstable();
    assert_eq!(listed, codes);
}
