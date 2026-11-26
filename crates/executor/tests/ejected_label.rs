//! W268/W269: the confined executor writes ejected vhost copies, so their
//! directory must carry the generation type it already manages. Under the
//! default `etc_t`, every eject failed with EACCES since W172; a product
//! test that ties `EJECTED_DIR` to the same type as `INCLUDE_DIR` would have
//! caught the missing file-context before a live rehearsal.

const FC: &str = include_str!("../../../policy/selinux/rustiron_executor.fc");

fn context_for(path: &str) -> &'static str {
    let want = format!("{path}(/.*)?");
    FC.lines()
        .find(|l| l.split_whitespace().next() == Some(want.as_str()))
        .unwrap_or_else(|| panic!("no file context for {want}"))
}

#[test]
fn ejected_dir_carries_the_generation_type() {
    let line = context_for(rustiron_executor::ols::EJECTED_DIR);
    assert!(
        line.contains("system_u:object_r:rustiron_ols_generation_t,s0"),
        "{line}"
    );
}

#[test]
fn ejected_and_include_share_one_managed_type() {
    // The executor already `manage_*`s rustiron_ols_generation_t for
    // INCLUDE_DIR; ejecting must not invent a second type or fall back to
    // etc_t. Sharing the include's type is the subtractive fix (W268).
    let include = context_for(rustiron_executor::ols::INCLUDE_DIR);
    let ejected = context_for(rustiron_executor::ols::EJECTED_DIR);
    let type_of = |line: &str| -> String {
        line.split_whitespace()
            .last()
            .and_then(|c| c.strip_prefix("gen_context(")?.strip_suffix(')'))
            .unwrap_or_else(|| panic!("bad context in {line}"))
            .to_owned()
    };
    assert_eq!(type_of(include), type_of(ejected));
}
