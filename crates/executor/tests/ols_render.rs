//! Lab OLS generation rendering: deterministic text and content addressing.

use rustiron_contracts::{Id, approval::Hostname};
use rustiron_executor::{
    ExecutorError,
    ols::{
        AdoptedSite, ServedSite, digest, generation_digest, generation_id, managed_accounts,
        observe, prepare, proxy_vhost, render, render_with_tls, tls_folder, tls_live, vhost,
        vhost_digest,
    },
};
use std::{
    collections::BTreeMap,
    fs,
    os::{
        fd::OwnedFd,
        unix::fs::{DirBuilderExt, symlink},
    },
    path::PathBuf,
};

fn adopted() -> Vec<AdoptedSite> {
    vec![AdoptedSite {
        name: "site_a".to_owned(),
        hostname: Hostname::try_from("site-a.example.test".to_owned()).unwrap(),
        uid: 2001,
    }]
}

fn served(account: &str, host: &str) -> ServedSite {
    ServedSite {
        account: account.to_owned(),
        alias_hostname: None,
        hostname: Hostname::try_from(host.to_owned()).unwrap(),
        ejected: false,
        static_ejected: false,
        lscache: false,
        tls_alias: None,
        tls: None,
        acme: false,
        proxy: None,
    }
}

#[test]
fn generation_maps_every_site_to_its_own_vhost_and_socket() {
    let generation = render(
        "G0",
        "192.168.122.186:8090",
        &adopted(),
        &[served("rs_blog5", "blog5.example.test")],
    );
    assert_eq!(
        generation.keys().collect::<Vec<_>>(),
        ["rs_blog5.vhost", "vhosts.conf"]
    );
    let vhosts = String::from_utf8(generation["vhosts.conf"].clone()).unwrap();
    assert!(vhosts.contains("virtualHost site_a {\n vhRoot /srv/sites/site_a/\n configFile $SERVER_ROOT/conf/vhosts/site_a/vhconf.conf\n"));
    assert!(vhosts.contains(" configFile /etc/rustiron-ols/current/rs_blog5.vhost\n"));
    assert!(vhosts.ends_with("listener G0 {\n address 192.168.122.186:8090\n secure 0\n map site_a site-a.example.test\n map rs_blog5 blog5.example.test\n}\n"));
    let vhost = String::from_utf8(generation["rs_blog5.vhost"].clone()).unwrap();
    assert!(vhost.starts_with("docRoot /srv/sites/rs_blog5/html/\nvhDomain blog5.example.test\n"));
    assert!(vhost.contains(" address uds://run/rustiron-sites/rs_blog5.sock\n"));
    assert!(vhost.contains(" autoStart 0\n"));
    assert!(vhost.contains(" add lsapi:lsphp_rs_blog5 php\n"));
    assert!(
        !vhost.contains("extUser"),
        "OLS never starts or switches identity for site PHP"
    );
}

#[test]
fn identical_inputs_give_identical_ids_and_any_change_moves_them() {
    let one = render(
        "G0",
        "192.168.122.186:8090",
        &adopted(),
        &[served("rs_blog5", "blog5.example.test")],
    );
    let again = render(
        "G0",
        "192.168.122.186:8090",
        &adopted(),
        &[served("rs_blog5", "blog5.example.test")],
    );
    assert_eq!(digest(&one), digest(&again));
    let id = generation_id(&digest(&one));
    assert!(id.as_str().starts_with('r') && id.as_str().len() == 17);
    let other_host = render(
        "G0",
        "192.168.122.186:8090",
        &adopted(),
        &[served("rs_blog5", "blog6.example.test")],
    );
    let adopted_only = render("G0", "192.168.122.186:8090", &adopted(), &[]);
    assert_ne!(digest(&one), digest(&other_host));
    assert_ne!(digest(&one), digest(&adopted_only));
    let mut renamed = one.clone();
    let bytes = renamed.remove("rs_blog5.vhost").unwrap();
    renamed.insert("rs_blog5.vhostx".to_owned(), bytes);
    assert_ne!(
        digest(&one),
        digest(&renamed),
        "names are part of the digest"
    );
}

/// Root only: a generation digest refuses a symlink or an extra hard link,
/// and the staging does not write through or move an existing generation
/// name that is a link (W384: only a root-owned folder is moved aside).
#[test]
#[ignore = "include files must be root-owned"]
fn include_directory_refuses_symlink_and_hardlink() {
    let root = PathBuf::from(format!("/tmp/ri-include-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::DirBuilder::new().mode(0o755).create(&root).unwrap();
    let generation = root.join("generations/gen_old");
    fs::create_dir_all(&generation).unwrap();
    fs::write(generation.join("site.vhost"), b"vhost\n").unwrap();
    symlink("generations/gen_old", root.join("current")).unwrap();
    let include = OwnedFd::from(fs::File::open(&root).unwrap());
    let id = Id::try_from("gen_old".to_owned()).unwrap();
    assert!(observe(&include).is_ok());

    fs::remove_file(generation.join("site.vhost")).unwrap();
    symlink("/etc/hostname", generation.join("site.vhost")).unwrap();
    assert_eq!(
        generation_digest(&include, &id),
        Err(ExecutorError::RegistryUnavailable)
    );
    assert_eq!(
        vhost_digest(&include, "site"),
        Err(ExecutorError::RegistryUnavailable)
    );
    assert_eq!(
        fs::read_link(generation.join("site.vhost")).unwrap(),
        PathBuf::from("/etc/hostname")
    );

    fs::remove_file(generation.join("site.vhost")).unwrap();
    fs::write(generation.join("site.vhost"), b"vhost\n").unwrap();
    fs::hard_link(generation.join("site.vhost"), root.join("extra")).unwrap();
    assert_eq!(
        generation_digest(&include, &id),
        Err(ExecutorError::RegistryUnavailable)
    );
    assert_eq!(
        vhost_digest(&include, "site"),
        Err(ExecutorError::RegistryUnavailable)
    );
    fs::remove_file(root.join("extra")).unwrap();
    assert!(generation_digest(&include, &id).is_ok());
    assert!(vhost_digest(&include, "site").unwrap().is_some());
    assert_eq!(vhost_digest(&include, "missing").unwrap(), None);

    fs::remove_file(root.join("current")).unwrap();
    symlink("/etc/passwd", root.join("current")).unwrap();
    assert_eq!(observe(&include), Err(ExecutorError::RegistryUnavailable));

    let planted = root.join("generations/gen_new");
    symlink("/etc", &planted).unwrap();
    let mut files = BTreeMap::new();
    files.insert("vhosts.conf".to_owned(), b"nope\n".to_vec());
    assert_eq!(
        prepare(
            &include,
            &Id::try_from("gen_new".to_owned()).unwrap(),
            &files,
            &Id::try_from("op_render".to_owned()).unwrap(),
        ),
        Err(ExecutorError::Collision)
    );
    assert!(planted.symlink_metadata().unwrap().file_type().is_symlink());
    let _ = fs::remove_dir_all(&root);
}

/// Root, lab VM only: the live include directory opens and observes.
#[test]
#[ignore = "requires root on the lab VM"]
fn root_observes_the_live_include_generation() {
    let include = rustiron_executor::ols::open_include().unwrap();
    let (id, digest) = rustiron_executor::ols::observe(&include).unwrap();
    println!("{} {}", id.as_str(), digest.as_str());
}

#[test]
fn an_ejected_site_points_at_its_standalone_vhost_and_leaves_the_generation() {
    let managed = served("rs_blog9", "blog9.example.test");
    let ejected = ServedSite {
        ejected: true,
        ..managed.clone()
    };
    let before = render("G0", "192.168.122.186:8090", &adopted(), &[managed]);
    let after = render("G0", "192.168.122.186:8090", &adopted(), &[ejected]);
    assert!(before.contains_key("rs_blog9.vhost"));
    assert!(
        !after.contains_key("rs_blog9.vhost"),
        "no managed file once ejected"
    );
    let vhosts = String::from_utf8(after["vhosts.conf"].clone()).unwrap();
    assert!(vhosts.contains("configFile /etc/rustiron-ejected/rs_blog9/vhost.conf\n"));
    assert!(
        vhosts.contains(" map rs_blog9 blog9.example.test\n"),
        "still served"
    );
    // W387 (D-037): the file written at eject is the standalone render
    // (`ejected_vhost`, tests/ejected_vhost.rs), not a copy of this one.
    assert_eq!(
        before["rs_blog9.vhost"],
        vhost("rs_blog9", "blog9.example.test", false).into_bytes(),
    );
    assert_ne!(digest(&before), digest(&after));
}

/// Root only (W188): an eject naming a generation that does not exist is a
/// changed precondition, not an access failure; an existing one lists its
/// managed accounts.
#[test]
#[ignore = "include files must be root-owned"]
fn managed_accounts_of_a_missing_generation_is_a_changed_precondition() {
    let root = PathBuf::from(format!("/tmp/ri-include-missing-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::DirBuilder::new().mode(0o755).create(&root).unwrap();
    let generation = root.join("generations/gen_old");
    fs::create_dir_all(&generation).unwrap();
    fs::write(generation.join("rs_site.vhost"), b"vhost\n").unwrap();
    symlink("generations/gen_old", root.join("current")).unwrap();
    let include = OwnedFd::from(fs::File::open(&root).unwrap());
    assert_eq!(
        managed_accounts(&include, &Id::try_from("gen_old".to_owned()).unwrap()),
        Ok(vec!["rs_site".to_owned()])
    );
    assert_eq!(
        managed_accounts(&include, &Id::try_from("r0000".to_owned()).unwrap()),
        Err(ExecutorError::PreconditionChanged)
    );
    let _ = fs::remove_dir_all(&root);
}

/// Root only: a generation file or generation directory not owned by root is
/// refused, so a non-root writer cannot feed the include.
/// (`managed_accounts` only lists names; activation and eject still verify
/// the live generation through `observe` before any effect.)
#[test]
#[ignore = "include files must be root-owned"]
fn include_directory_refuses_entries_not_owned_by_root() {
    use std::os::unix::fs::lchown;
    let root = PathBuf::from(format!("/tmp/ri-include-owner-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::DirBuilder::new().mode(0o755).create(&root).unwrap();
    let generation = root.join("generations/gen_old");
    fs::create_dir_all(&generation).unwrap();
    fs::write(generation.join("rs_site.vhost"), b"vhost\n").unwrap();
    symlink("generations/gen_old", root.join("current")).unwrap();
    let include = OwnedFd::from(fs::File::open(&root).unwrap());
    let id = Id::try_from("gen_old".to_owned()).unwrap();
    assert!(generation_digest(&include, &id).is_ok());

    for (path, refused) in [
        (
            generation.join("rs_site.vhost"),
            ExecutorError::RegistryUnavailable,
        ),
        (generation.clone(), ExecutorError::AccessDenied),
    ] {
        lchown(&path, Some(65534), None).unwrap();
        assert_eq!(
            generation_digest(&include, &id),
            Err(refused),
            "{}",
            path.display()
        );
        lchown(&path, Some(0), None).unwrap();
    }
    // The `current` link's owner is not checked: only root can replace it in
    // the root-owned include, and its target must still be a root-owned
    // generation.
    lchown(root.join("current"), Some(65534), None).unwrap();
    assert!(observe(&include).is_ok());
    let _ = fs::remove_dir_all(&root);
}

/// D-068 (W478): the identity file is served with rewriting off, so a site's
/// own rules (a forced HTTPS redirect) cannot fail the activation probe.
/// D-073 (W487): the PHP health context, appended after the probe context.
const PHP_HEALTH: &str = "context /rustiron-php-health.php {\n location /usr/share/rustiron/ols/php-health.php\n allowBrowse 1\n rewrite {\n  enable 0\n }\n}\n";

fn probe_context(account: &str) -> String {
    format!(
        "context /rustiron-site.txt {{\n location /srv/sites/{account}/html/rustiron-site.txt\n allowBrowse 1\n rewrite {{\n  enable 0\n }}\n}}\n"
    )
}

/// W370: a vhost that is not opted in turns the cache module off
/// (`ls_enabled 0`), so a public mark from its PHP is neither stored in the
/// parent's shared default storage nor served. This moves the W336 pins on
/// purpose; the W336 text is still the exact prefix.
/// W336 pins: generation `8f08795a…3ee0bd`, vhost `0f16421f…cf8419`.
/// W370 pins (before D-068): generation `3f09e515…7d3e1b`, vhost `e4626ea3…f362a4`.
/// D-068 pins (before D-073): generation `7f6f0e71…14c591`, vhost `b768777f…178bc52`.
#[test]
fn an_unopted_vhost_turns_the_cache_module_off_with_pinned_bytes() {
    use sha2::{Digest, Sha256};
    let sha = |text: &str| {
        let bytes: [u8; 32] = Sha256::digest(text.as_bytes()).into();
        rustiron_contracts::approval::Sha256Digest::from_bytes(bytes)
            .as_str()
            .to_owned()
    };
    let plain = served("rs_blog5", "blog5.example.test");
    let generation = render("G0", "192.168.122.186:8090", &adopted(), &[plain]);
    assert_eq!(
        digest(&generation).as_str(),
        "6bc6610b772966fd5ab82799778411346b98452e1151fc0d494a4e6c314426c5"
    );
    let text = vhost("rs_blog5", "blog5.example.test", false);
    assert_eq!(
        sha(&text),
        "c950c48e303a68ad87b058563376372c84718c0cddb6bb3d73ebe3f00c468dd5"
    );
    let w336 = text
        .strip_suffix(PHP_HEALTH)
        .expect("the D-073 PHP health context is appended last")
        .strip_suffix(&probe_context("rs_blog5"))
        .expect("the D-068 probe context comes before it")
        .strip_suffix("module cache {\n ls_enabled 0\n}\n")
        .expect("the off block is appended last");
    assert_eq!(
        sha(w336),
        "0f16421f95f364c163912c261b263bb5e5f49843108eb12cf38d012270cf8419",
        "the W336 text is unchanged before the block"
    );
    for absent in ["storagePath", "modcache", "RewriteCond", "enableCache"] {
        assert!(!text.contains(absent), "{absent:?} rendered:\n{text}");
    }
}

/// D-028 item 2 (W336, W370): an opted-in vhost gets its own cache storage
/// with the module's own cache switches off, so only a response that the
/// site's LiteSpeed Cache plugin marks cacheable is stored. W370 adds one
/// vhost rewrite rule: a GET or HEAD with a WordPress post-password cookie
/// and no login cookie turns the cache module off for that request
/// (`modcache:0`, honoured by OLS 1.9.4 at URI_MAP after the vhost rewrite),
/// so that visitor never gets the cached password form and the unlocked page
/// is never stored. Login cookies are not matched: those requests keep the
/// plugin's purge headers.
#[test]
fn lscache_renders_per_site_storage_and_the_post_password_bypass() {
    let plain = served("rs_blog5", "blog5.example.test");
    let cached = ServedSite {
        lscache: true,
        ..served("rs_w336a", "w336a.example.test")
    };
    let generation = render(
        "G0",
        "192.168.122.186:8090",
        &adopted(),
        &[plain.clone(), cached],
    );
    assert_eq!(
        render("G0", "192.168.122.186:8090", &adopted(), &[plain])["rs_blog5.vhost"],
        generation["rs_blog5.vhost"],
        "an unopted vhost keeps its exact bytes beside an opted-in one"
    );
    let text = String::from_utf8(generation["rs_w336a.vhost"].clone()).unwrap();
    let block = "module cache {\n ls_enabled 1\n enableCache 0\n enablePrivateCache 0\n storagePath /usr/local/lsws/cachedata/rs_w336a\n}\n";
    let rules = concat!(
        "rewrite {\n enable 1\n autoLoadHtaccess 1\n rules <<<END_rules\n",
        "RewriteCond %{REQUEST_METHOD} ^(GET|HEAD)$\n",
        "RewriteCond %{HTTP_COOKIE} (^|;\\s*)wp-postpass_[^=;]*=\n",
        "RewriteCond %{HTTP_COOKIE} !(^|;\\s*)wordpress_logged_in_[^=;]*=\n",
        "RewriteRule .* - [E=modcache:0]\n",
        " END_rules\n}\n",
    );
    let unopted = vhost("rs_w336a", "w336a.example.test", false);
    let probe = probe_context("rs_w336a");
    let w336 = unopted
        .strip_suffix(PHP_HEALTH)
        .and_then(|text| text.strip_suffix(&probe))
        .and_then(|text| text.strip_suffix("module cache {\n ls_enabled 0\n}\n"))
        .unwrap();
    assert_eq!(
        text,
        format!(
            "{}{block}{probe}{PHP_HEALTH}",
            w336.replace("rewrite {\n enable 1\n autoLoadHtaccess 1\n}\n", rules)
        ),
        "only the rewrite rule and the storage block differ"
    );
    assert_eq!(text.matches("rewrite {\n enable 1\n").count(), 1);
    assert_eq!(text.matches("module cache {").count(), 1);
    for absent in [
        "enableCache 1",
        "enablePrivateCache 1",
        "ls_enabled 0",
        "comment_author_",
        "E=Cache-Control",
        "expireInSeconds",
    ] {
        assert!(!text.contains(absent), "{absent:?} rendered:\n{text}");
    }
    let vhosts = String::from_utf8(generation["vhosts.conf"].clone()).unwrap();
    assert!(
        !vhosts.contains("cache"),
        "nothing at listener or server scope"
    );
}

#[test]
fn a_frozen_site_answers_503_with_retry_after_from_a_root_owned_page_outside_its_docroot() {
    let text = vhost("rs_blog13", "blog13.example.test", false);
    assert!(
        text.contains("errorpage 503 {\n url /.rustiron-errors/503.html\n}\n"),
        "{text}"
    );
    let context = text
        .split("context /.rustiron-errors/ {")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .expect("error-page context");
    assert!(
        context.contains("location /srv/sites/rs_blog13/errors/"),
        "{context}"
    );
    assert!(context.contains("Retry-After 10"), "{context}");
    assert!(
        context.contains("rewrite {\n  enable 0\n }"),
        "no WordPress rewrite to PHP: {context}"
    );
    assert!(
        !context.contains("/html/"),
        "the page is outside the site web folder"
    );
    assert!(!context.contains("lsapi"), "the page is static");
    assert!(!rustiron_executor::ols::MAINTENANCE_PAGE.contains("<?"));
}

fn certificate(fill: char) -> rustiron_contracts::approval::Sha256Digest {
    rustiron_contracts::approval::Sha256Digest::try_from(fill.to_string().repeat(64)).unwrap()
}

/// W460 (D-059 slice 1): without an enrolled TLS address the render is the
/// plain render, byte for byte, so no enrolled generation changes. W461:
/// with one, every managed vhost serves only its challenge webroot, and no
/// TLS listener renders until a site has a certificate.
#[test]
fn without_a_certificate_the_tls_render_is_the_plain_render() {
    let webroot = ServedSite {
        acme: true,
        ..served("rs_blog5", "blog5.example.test")
    };
    let sites = [webroot, served("rs_blog8", "blog8.example.test")];
    let plain = render("G0", "192.168.122.186:8090", &adopted(), &sites);
    assert_eq!(
        render_with_tls("G0", "192.168.122.186:8090", None, &adopted(), &sites),
        plain
    );
    let enrolled = render_with_tls(
        "G0",
        "192.168.122.186:8090",
        Some("192.168.122.186:8443"),
        &adopted(),
        &sites,
    );
    assert_eq!(enrolled["vhosts.conf"], plain["vhosts.conf"]);
    let vhost = String::from_utf8(enrolled["rs_blog5.vhost"].clone()).unwrap();
    let base = String::from_utf8(plain["rs_blog5.vhost"].clone()).unwrap();
    assert_eq!(
        vhost.strip_prefix(base.as_str()).unwrap(),
        "context /.well-known/acme-challenge/ {\n location /srv/sites/rs_blog5/acme/.well-known/acme-challenge/\n allowBrowse 1\n rewrite {\n  enable 0\n }\n}\n"
    );
    // W461: a site without its webroot gets no context; OLS would refuse it.
    assert_eq!(enrolled["rs_blog8.vhost"], plain["rs_blog8.vhost"]);
}

/// W460: a site with a certificate gets a `vhssl` block, and one SNI
/// listener maps exactly the sites that have one. D-064: an ejected site
/// with a certificate stays on it; its `vhssl` is in its standalone vhost. Nothing overrides
/// the D-039 parent defaults.
#[test]
fn a_certificate_adds_the_vhost_ssl_block_and_one_sni_listener() {
    let secure = ServedSite {
        tls: Some(certificate('c')),
        ..served("rs_blog6", "blog6.example.test")
    };
    let ejected = ServedSite {
        ejected: true,
        tls: Some(certificate('d')),
        ..served("rs_blog7", "blog7.example.test")
    };
    let plain = served("rs_blog5", "blog5.example.test");
    let sites = [plain, secure, ejected];
    let generation = render_with_tls(
        "G0",
        "192.168.122.186:8090",
        Some("192.168.122.186:8443"),
        &adopted(),
        &sites,
    );
    assert_eq!(
        tls_folder("rs_blog6", &certificate('c')),
        format!("/etc/rustiron-tls/rs_blog6/{}", "c".repeat(64))
    );
    // D-060: the generation names the site's live link, not the digest.
    let folder = tls_live("rs_blog6");
    assert_eq!(folder, "/etc/rustiron-tls/rs_blog6/live");
    let vhost6 = String::from_utf8(generation["rs_blog6.vhost"].clone()).unwrap();
    assert!(vhost6.ends_with(&format!(
        "vhssl {{\n keyFile {folder}/key.pem\n certFile {folder}/fullchain.pem\n certChain 1\n}}\n"
    )));
    let vhost5 = String::from_utf8(generation["rs_blog5.vhost"].clone()).unwrap();
    assert!(!vhost5.contains("vhssl"));
    let main = String::from_utf8(generation["vhosts.conf"].clone()).unwrap();
    let tls = &main[main.find("listener G0TLS {").expect("a TLS listener")..];
    assert_eq!(
        tls,
        format!(
            "listener G0TLS {{\n address 192.168.122.186:8443\n secure 1\n keyFile {folder}/key.pem\n certFile {folder}/fullchain.pem\n certChain 1\n map rs_blog6 blog6.example.test\n map rs_blog7 blog7.example.test\n}}\n"
        )
    );
    assert!(
        !generation.contains_key("rs_blog7.vhost"),
        "the ejected vhost is not in the generation"
    );
    for text in [&main, &vhost6] {
        for forbidden in [
            "ciphers",
            "enableQuic",
            "sslProtocol",
            "/var/lib/rustiron-acme",
        ] {
            assert!(!text.contains(forbidden), "{forbidden}");
        }
    }
    // The plain listener still maps every site.
    assert!(main.contains(" map rs_blog5 blog5.example.test\n"));
    assert!(main.contains(" map rs_blog7 blog7.example.test\n"));
    // Without an enrolled TLS address there is no TLS listener.
    let unenrolled = render_with_tls("G0", "192.168.122.186:8090", None, &adopted(), &sites);
    assert!(
        !String::from_utf8(unenrolled["vhosts.conf"].clone())
            .unwrap()
            .contains("G0TLS")
    );
    // D-060: a renewal (another digest) keeps the same generation.
    let other = ServedSite {
        tls: Some(certificate('e')),
        ..served("rs_blog6", "blog6.example.test")
    };
    assert_eq!(
        digest(&generation),
        digest(&render_with_tls(
            "G0",
            "192.168.122.186:8090",
            Some("192.168.122.186:8443"),
            &adopted(),
            &[
                served("rs_blog5", "blog5.example.test"),
                other,
                sites[2].clone()
            ],
        ))
    );
}

#[test]
fn an_import_alias_is_mapped_only_on_http() {
    let with_alias = ServedSite {
        alias_hostname: Some(Hostname::try_from("alias.example.test".to_owned()).unwrap()),
        tls: Some(certificate('c')),
        ..served("rs_blog6", "blog6.example.test")
    };
    let generation = render_with_tls(
        "G0",
        "127.0.0.1:8090",
        Some("127.0.0.1:8443"),
        &[],
        &[with_alias],
    );
    let config = std::str::from_utf8(&generation["vhosts.conf"]).unwrap();
    let (http, tls) = config.split_once("listener G0TLS {").unwrap();
    assert!(http.contains(" map rs_blog6 blog6.example.test,alias.example.test\n"));
    assert!(tls.contains(" map rs_blog6 blog6.example.test\n"));
    assert!(!tls.contains("alias.example.test"));
}

#[test]
fn an_installed_pair_maps_both_names_on_each_listener() {
    let alias = Hostname::try_from("alias.example.test".to_owned()).unwrap();
    let site = ServedSite {
        alias_hostname: Some(alias.clone()),
        tls: Some(certificate('c')),
        tls_alias: Some(alias),
        ..served("rs_blog6", "blog6.example.test")
    };
    let generation = render_with_tls("G0", "127.0.0.1:8090", Some("127.0.0.1:8443"), &[], &[site]);
    let config = std::str::from_utf8(&generation["vhosts.conf"]).unwrap();
    assert_eq!(
        config
            .lines()
            .filter(|line| *line == " map rs_blog6 blog6.example.test,alias.example.test")
            .count(),
        2,
    );
}

fn route(prefix: &str, port: u16) -> rustiron_contracts::approval::ProxyRoute {
    rustiron_contracts::approval::ProxyRoute {
        prefix: prefix.to_owned(),
        port,
    }
}

/// W574 (D-095): a proxy site's vhost forwards each route to its loopback
/// port through one proxy app per port, carries each WebSocket path in a
/// `websocket` block, serves the identity file from disk, runs no script,
/// and has no PHP, rewrite, or maintenance page. With TLS it gets the ACME
/// context and `vhssl` as any site.
#[test]
fn a_proxy_site_forwards_its_routes_to_loopback_and_runs_no_script() {
    let routes = rustiron_journal::ProxyFacts {
        routes: vec![
            route("/", 3100),
            route("/api/", 3101),
            route("/downloads/", 3101),
        ],
        websockets: vec![route("/ws/", 3100)],
    };
    let text = proxy_vhost("rs_ytproxy", "yt.example.test", &routes);
    assert_eq!(
        text,
        "docRoot /srv/sites/rs_ytproxy/html/\nvhDomain yt.example.test\n\
extprocessor proxy_3100 {\n type proxy\n address 127.0.0.1:3100\n maxConns 100\n initTimeout 60\n retryTimeout 0\n respBuffer 0\n}\n\
extprocessor proxy_3101 {\n type proxy\n address 127.0.0.1:3101\n maxConns 100\n initTimeout 60\n retryTimeout 0\n respBuffer 0\n}\n\
module cache {\n ls_enabled 0\n}\n\
context /rustiron-site.txt {\n location /srv/sites/rs_ytproxy/html/rustiron-site.txt\n allowBrowse 1\n rewrite {\n  enable 0\n }\n}\n\
context / {\n type proxy\n handler proxy_3100\n addDefaultCharset off\n}\n\
context /api/ {\n type proxy\n handler proxy_3101\n addDefaultCharset off\n}\n\
context /downloads/ {\n type proxy\n handler proxy_3101\n addDefaultCharset off\n}\n\
context /ws/ {\n type proxy\n handler proxy_3100\n addDefaultCharset off\n}\n\
websocket /ws/ {\n address 127.0.0.1:3100\n}\n"
    );
    for absent in [
        "lsapi",
        "scripthandler",
        "rewrite {\n enable 1",
        "errorpage",
        ".htaccess",
    ] {
        assert!(!text.contains(absent), "{absent}");
    }
    // W577-F1: plain requests under a WebSocket path follow the routes: a
    // path under /api/ gets the /api/ port; a path that is also a route
    // (Arcane: / and websocket /) gets no second context.
    let nested = rustiron_journal::ProxyFacts {
        routes: vec![route("/", 3100), route("/api/", 3101)],
        websockets: vec![route("/api/live/", 3102), route("/", 3100)],
    };
    let nested = proxy_vhost("rs_ytproxy", "yt.example.test", &nested);
    assert!(nested.contains(
        "context /api/live/ {\n type proxy\n handler proxy_3101\n addDefaultCharset off\n}\n"
    ));
    assert_eq!(nested.matches("context / {").count(), 1, "{nested}");
    assert!(nested.contains("websocket /api/live/ {\n address 127.0.0.1:3102\n}\n"));
    let proxy = ServedSite {
        acme: true,
        tls: Some(certificate('a')),
        proxy: Some(routes),
        ..served("rs_ytproxy", "yt.example.test")
    };
    let sites = [served("rs_blog5", "blog5.example.test"), proxy];
    let generation = render_with_tls(
        "G0",
        "192.168.122.186:8090",
        Some("192.168.122.186:8443"),
        &adopted(),
        &sites,
    );
    let vhosts = String::from_utf8(generation["vhosts.conf"].clone()).unwrap();
    assert!(vhosts.contains("virtualHost rs_ytproxy {\n vhRoot /srv/sites/rs_ytproxy/\n configFile /etc/rustiron-ols/current/rs_ytproxy.vhost\n allowSymbolLink 0\n enableScript 0\n"));
    assert!(vhosts.contains("virtualHost rs_blog5 {\n vhRoot /srv/sites/rs_blog5/\n configFile /etc/rustiron-ols/current/rs_blog5.vhost\n allowSymbolLink 0\n enableScript 1\n"));
    assert!(vhosts.contains(" map rs_ytproxy yt.example.test\n"));
    let vhost = String::from_utf8(generation["rs_ytproxy.vhost"].clone()).unwrap();
    let rest = vhost.strip_prefix(text.as_str()).unwrap();
    assert!(rest.starts_with("context /.well-known/acme-challenge/ {\n location /srv/sites/rs_ytproxy/acme/.well-known/acme-challenge/\n"));
    assert!(rest.ends_with("vhssl {\n keyFile /etc/rustiron-tls/rs_ytproxy/live/key.pem\n certFile /etc/rustiron-tls/rs_ytproxy/live/fullchain.pem\n certChain 1\n}\n"));
    // The WordPress site beside it is unchanged.
    assert!(
        String::from_utf8(generation["rs_blog5.vhost"].clone())
            .unwrap()
            .contains(" add lsapi:lsphp_rs_blog5 php\n")
    );
}

/// D-097: an ejected single-name static site disables scripting in the parent
/// virtualHost block, points at its standalone vhost, keeps its HTTP map, and
/// keeps its TLS map only when certified.
#[test]
fn a_single_name_static_ejected_site_disables_scripts_and_preserves_maps() {
    let http_only = ServedSite {
        ejected: true,
        static_ejected: true,
        ..served("rs_plain", "plain.example.test")
    };
    let https = ServedSite {
        ejected: true,
        static_ejected: true,
        tls: Some(certificate('b')),
        ..served("rs_secure", "secure.example.test")
    };
    let wp = ServedSite {
        ejected: true,
        ..served("rs_wp", "wp.example.test")
    };
    let generation = render_with_tls(
        "G0",
        "127.0.0.1:8090",
        Some("127.0.0.1:8443"),
        &adopted(),
        &[http_only, https, wp],
    );
    assert!(!generation.contains_key("rs_plain.vhost"));
    assert!(!generation.contains_key("rs_secure.vhost"));
    assert!(!generation.contains_key("rs_wp.vhost"));
    let vhosts = String::from_utf8(generation["vhosts.conf"].clone()).unwrap();
    assert!(vhosts.contains(
        "virtualHost rs_plain {\n vhRoot /srv/sites/rs_plain/\n configFile /etc/rustiron-ejected/rs_plain/vhost.conf\n allowSymbolLink 0\n enableScript 0\n"
    ));
    assert!(vhosts.contains(
        "virtualHost rs_secure {\n vhRoot /srv/sites/rs_secure/\n configFile /etc/rustiron-ejected/rs_secure/vhost.conf\n allowSymbolLink 0\n enableScript 0\n"
    ));
    assert!(vhosts.contains(
        "virtualHost rs_wp {\n vhRoot /srv/sites/rs_wp/\n configFile /etc/rustiron-ejected/rs_wp/vhost.conf\n allowSymbolLink 0\n enableScript 1\n"
    ));
    let tls_idx = vhosts.find("listener G0TLS {").expect("TLS listener");
    let (http, tls) = vhosts.split_at(tls_idx);
    assert!(http.contains(" map rs_plain plain.example.test\n"));
    assert!(http.contains(" map rs_secure secure.example.test\n"));
    assert!(!tls.contains("rs_plain"));
    assert!(tls.contains(" map rs_secure secure.example.test\n"));
}
