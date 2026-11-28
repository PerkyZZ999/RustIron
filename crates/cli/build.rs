//! W784 (D-106): lists the Docs & KB guides for `rustiron-mcp` resources.
//!
//! The guides live in `console/kb/` (the one source for the Console and
//! docs.rustiron.app). A build of the whole tree embeds every `*.md` there; a
//! build of the crate alone (the isolated feature and doctor gates) finds no
//! folder and embeds none, so the crate stays self-contained.

use std::{env, fs, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let dir = manifest.join("../../console/kb");
    println!("cargo::rerun-if-changed=../../console/kb");
    let mut slugs: Vec<String> = fs::read_dir(&dir)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
                .filter_map(|name| name.strip_suffix(".md").map(str::to_owned))
                .filter(|slug| slug != "README")
                .collect()
        })
        .unwrap_or_default();
    slugs.sort();
    let mut code = String::from(
        "/// Every guide as (slug, Markdown), in file-name order.\npub(crate) const GUIDES: &[(&str, &str)] = &[\n",
    );
    for slug in &slugs {
        let path = dir.join(format!("{slug}.md"));
        code.push_str(&format!(
            "    ({slug:?}, include_str!({:?})),\n",
            path.display().to_string()
        ));
    }
    code.push_str("];\n");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap_or_default()).join("guides.rs");
    if let Err(error) = fs::write(&out, code) {
        panic!("cannot write {}: {error}", out.display());
    }
}
