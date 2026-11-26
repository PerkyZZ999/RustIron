//! W387 (D-037): the standalone vhost that `site_eject` writes. OpenLiteSpeed
//! starts the site's PHP itself, as the site account, so the site needs no
//! Rustiron unit, socket, path, or SELinux module after an uninstallation.

use rustiron_executor::ols::{
    EJECTED_PHP_SOCKET_DIR, LSAPI_MAX_CONNS, ejected_single_static_vhost, ejected_vhost,
    unit_children, vhost,
};
use sha2::{Digest, Sha256};

/// The site PHP template that a managed site runs under.
const PHP_UNIT: &str = include_str!("../../../packaging/systemd/rustiron-site-php@.service");

fn lines(text: &str) -> Vec<&str> {
    text.lines().collect()
}

/// The lines between `<head> {` and the closing `}` of one block.
fn block<'a>(text: &'a str, head: &str) -> Vec<&'a str> {
    text.lines()
        .skip_while(|line| *line != format!("{head} {{"))
        .skip(1)
        .take_while(|line| *line != "}")
        .collect()
}

#[test]
fn the_ejected_vhost_starts_php_as_the_site_account() {
    let text = ejected_vhost("rs_blog9", "blog9.example.test", false, false);
    let php = block(&text, "extprocessor lsphp_rs_blog9");
    for wanted in [
        " type lsapi",
        " address uds://tmp/lshttpd/rs_blog9.sock",
        " autoStart 1",
        " path /usr/local/lsws/lsphp84/bin/lsphp",
        " extUser rs_blog9",
        " extGroup rs_blog9",
        " instances 1",
        " env TMPDIR=/srv/sites/rs_blog9/tmp",
    ] {
        assert!(php.contains(&wanted), "missing {wanted:?} in {php:?}");
    }
    assert!(text.contains("scripthandler {\n add lsapi:lsphp_rs_blog9 php\n}\n"));
    assert_eq!(EJECTED_PHP_SOCKET_DIR, "/tmp/lshttpd");
}

#[test]
fn the_ejected_vhost_names_no_rustiron_path_unit_or_page() {
    for lscache in [false, true] {
        let text = ejected_vhost("rs_blog9", "blog9.example.test", lscache, false);
        assert!(!text.to_ascii_lowercase().contains("rustiron"), "{text}");
        assert!(
            !text.contains("/run/"),
            "no runtime socket of a unit: {text}"
        );
        assert!(!text.contains("autoStart 0"), "OLS starts the PHP: {text}");
        assert!(
            !text.contains("errorpage"),
            "no Rustiron maintenance page: {text}"
        );
    }
}

#[test]
fn the_ejected_vhost_keeps_the_php_capacity_of_the_managed_unit() {
    let text = ejected_vhost("rs_blog9", "blog9.example.test", false, false);
    let php = block(&text, "extprocessor lsphp_rs_blog9");
    let children = unit_children(PHP_UNIT).expect("the unit sets PHP_LSAPI_CHILDREN");
    assert!(php.contains(&format!(" env PHP_LSAPI_CHILDREN={children}").as_str()));
    assert!(php.contains(&format!(" maxConns {LSAPI_MAX_CONNS}").as_str()));
    let requests = PHP_UNIT
        .split_whitespace()
        .find_map(|word| word.strip_prefix("PHP_LSAPI_MAX_REQUESTS="))
        .expect("the unit sets PHP_LSAPI_MAX_REQUESTS");
    assert!(php.contains(&format!(" env PHP_LSAPI_MAX_REQUESTS={requests}").as_str()));
    // OLS sets rlimits for the processes it starts. W387 run 1: a process
    // limit under 248 is raised by OLS itself, so the bound is above it.
    for wanted in [
        " memSoftLimit 2047M",
        " memHardLimit 2047M",
        " procSoftLimit 400",
        " procHardLimit 500",
    ] {
        assert!(php.contains(&wanted), "missing {wanted:?}");
    }
}

#[test]
fn the_ejected_vhost_keeps_the_site_settings_of_the_managed_vhost() {
    for lscache in [false, true] {
        let ejected = ejected_vhost("rs_blog9", "blog9.example.test", lscache, false);
        let managed = vhost("rs_blog9", "blog9.example.test", lscache);
        assert_eq!(
            lines(&ejected)[..3],
            lines(&managed)[..3],
            "docRoot, vhDomain, gzip"
        );
        for head in ["index", "phpIniOverride", "rewrite", "module cache"] {
            assert_eq!(block(&ejected, head), block(&managed, head), "{head}");
        }
        assert_eq!(
            ejected.contains("storagePath /usr/local/lsws/cachedata/rs_blog9"),
            lscache
        );
    }
}

/// The managed render changes only on purpose: generations that hosts store
/// keep their content address (W372 adoption compares bytes). D-068 (W478)
/// added the identity-probe context, and D-073 (W487) the PHP health context
/// (`b768777f…178bc52` and `9608d937…28dd200` before it); a host re-renders at its next activation.
#[test]
fn the_managed_vhost_bytes_are_unchanged() {
    let digest = |text: String| {
        Sha256::digest(text.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        digest(vhost("rs_blog5", "blog5.example.test", false)),
        "c950c48e303a68ad87b058563376372c84718c0cddb6bb3d73ebe3f00c468dd5"
    );
    assert_eq!(
        digest(vhost("rs_blog5", "blog5.example.test", true)),
        "fb024fc1ebfb9760f8c4619d3b1b53918038fed5896ae8e924aade9614eafc9c"
    );
}

/// D-064: an ejected site with a certificate keeps its `vhssl` block, which
/// names the installed chain; without one, the vhost has none.
#[test]
fn an_ejected_site_with_a_certificate_keeps_its_ssl_block() {
    let plain = ejected_vhost("rs_blog9", "blog9.example.test", false, false);
    let secure = ejected_vhost("rs_blog9", "blog9.example.test", false, true);
    assert!(!plain.contains("vhssl"));
    assert_eq!(
        secure.strip_prefix(plain.as_str()).unwrap(),
        "vhssl {\n keyFile /etc/rustiron-tls/rs_blog9/live/key.pem\n certFile /etc/rustiron-tls/rs_blog9/live/fullchain.pem\n certChain 1\n}\n"
    );
}

/// D-097: the standalone single-name static vhost uses its own marker,
/// denies PHP execution/source, keeps static redirects, and adds `vhssl`
/// only when served over HTTPS.
#[test]
fn the_single_name_static_ejected_vhost_denies_scripts_and_keeps_optional_tls() {
    let plain = ejected_single_static_vhost("rs_blog9", "blog9.example.test", false);
    assert!(plain.starts_with("# Standalone single-name static vhost\n"));
    assert!(plain.contains("docRoot /srv/sites/rs_blog9/html/\n"));
    assert!(plain.contains("vhDomain blog9.example.test\n"));
    assert!(plain.contains("indexFiles index.html\n"));
    assert!(plain.contains("autoLoadHtaccess 1\n"));
    assert!(plain.contains("RewriteRule \\.(php[0-9]*|phtml|phar)(/|$) - [F,NC,L]\n"));
    for forbidden in [
        "extprocessor",
        "scripthandler",
        "phpIniOverride",
        "errorpage",
        "vhssl",
        "rustiron",
    ] {
        assert!(
            !plain
                .to_ascii_lowercase()
                .contains(&forbidden.to_ascii_lowercase()),
            "unexpected {forbidden} in {plain}"
        );
    }
    let secure = ejected_single_static_vhost("rs_blog9", "blog9.example.test", true);
    assert_eq!(
        secure.strip_prefix(plain.as_str()).unwrap(),
        "vhssl {\n keyFile /etc/rustiron-tls/rs_blog9/live/key.pem\n certFile /etc/rustiron-tls/rs_blog9/live/fullchain.pem\n certChain 1\n}\n"
    );
}
