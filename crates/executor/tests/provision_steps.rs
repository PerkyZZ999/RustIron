//! Site provisioning steps: pure derivation/allocation here; the real root
//! steps run only on the lab VM (`--ignored`, as root).

use std::process::Command;

use rustiron_contracts::approval::{Hostname, Sha256Digest, SiteId};
use rustiron_executor::{
    ExecutorError,
    provision::{
        Ranges, SiteLayout, allocate_category, allocate_id, apply_labels, choose_category,
        choose_uid, create_account, create_database, create_directories, group_id,
        install_php_units, install_wordpress, name_taken, read_pinned, recorded_numbers,
        unpack_recipe, verify_site, write_credentials, write_wp_config,
    },
};

const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\nsite_a:x:2001:2001::/srv/sites/site_a:/sbin/nologin\nrs_old:x:3001:3001::/srv/sites/rs_old:/sbin/nologin\n";
const GROUP: &str = "root:x:0:\nnobody:x:65534:lsadm\nrs_old:x:3001:\nshared:x:3002:\n";

fn site(text: &str) -> SiteId {
    SiteId::try_from(text.to_owned()).unwrap()
}

#[test]
fn layout_is_derived_only_from_the_site_id() {
    let layout = SiteLayout::derive(&site("blog1"));
    assert_eq!(layout.account, "rs_blog1");
    assert_eq!(layout.root.to_str(), Some("/srv/sites/rs_blog1"));
}

#[test]
fn ids_go_above_any_used_uid_or_gid_and_respect_the_range() {
    assert_eq!(allocate_id(PASSWD, GROUP, (3001, 3099), &[]), Ok(3003));
    assert_eq!(
        allocate_id(PASSWD, GROUP, (3001, 3002), &[]),
        Err(ExecutorError::Capacity)
    );
    assert_eq!(
        allocate_id(PASSWD, GROUP, (2000, 2001), &[]),
        Err(ExecutorError::Capacity),
        "allocation never goes below an id in use"
    );
    assert_eq!(allocate_id(PASSWD, GROUP, (2000, 2002), &[]), Ok(2002));
}

#[test]
fn ids_and_categories_recorded_by_earlier_provisions_are_never_reused() {
    let recorded = [
        "Account rs_gone uid=3003".to_owned(),
        "Account rs_legacy".to_owned(),
        "Labels rs_gone level=s0:c201".to_owned(),
    ];
    let uids = recorded_numbers(&recorded, "uid=");
    assert_eq!(uids, [3003]);
    assert_eq!(allocate_id(PASSWD, GROUP, (3001, 3099), &uids), Ok(3004));
    assert_eq!(
        allocate_id(PASSWD, GROUP, (3001, 3003), &uids),
        Err(ExecutorError::Capacity)
    );
    let categories = recorded_numbers(&recorded, "level=s0:c");
    assert_eq!(categories, [201]);
    assert_eq!(allocate_category("", (201, 299), &categories), Ok(202));
}

#[test]
fn names_are_checked_in_both_databases() {
    assert!(name_taken(PASSWD, GROUP, "rs_old"));
    assert!(name_taken(PASSWD, GROUP, "shared"));
    assert!(!name_taken(PASSWD, GROUP, "rs_blog1"));
    assert!(!name_taken(PASSWD, GROUP, "rs_ol"), "no prefix matches");
    assert_eq!(group_id(GROUP, "nobody"), Some(65534));
    assert_eq!(group_id(GROUP, "absent"), None);
}

#[test]
fn categories_go_above_every_level_already_in_local_rules() {
    let rules = "/srv/sites/site_a(/.*)?  all files  system_u:object_r:httpd_sys_content_t:s0:c101\n/srv/sites/rs_x(/.*)?  all files  system_u:object_r:httpd_sys_content_t:s0:c201\n";
    assert_eq!(allocate_category(rules, (201, 299), &[]), Ok(202));
    assert_eq!(
        allocate_category(rules, (101, 101), &[]),
        Err(ExecutorError::Capacity)
    );
    assert_eq!(allocate_category("", (201, 299), &[]), Ok(201));
}

fn sh(script: &str) -> String {
    let out = Command::new("/bin/sh")
        .args(["-c", script])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// Root, lab VM only. Creates a throwaway site with every root step, checks
/// the result and the collision refusals, then the test (not the product)
/// removes what it made.
#[test]
#[ignore = "requires root on the lab VM"]
fn root_steps_create_a_complete_site_skeleton_and_refuse_collisions() {
    assert!(rustix::process::getuid().is_root());
    let layout = SiteLayout::derive(&site("tstep1"));
    let ranges = Ranges {
        uid: (3001, 3099),
        category: (201, 299),
    };
    let cleanup = format!(
        "systemctl disable --now rustiron-site-sandbox-check@{a}.timer rustiron-site-php@{a}.socket rustiron-site-php@{a}.service >/dev/null 2>&1; \
         rm -rf /etc/systemd/system/rustiron-site-php@{a}.service.d; systemctl daemon-reload; \
         semanage fcontext -d '/srv/sites/{a}/(tmp|logs)(/.*)?' 2>/dev/null; semanage fcontext -d '/srv/sites/{a}(/.*)?' 2>/dev/null; \
         mariadb -e \"DROP DATABASE IF EXISTS {a}; DROP USER IF EXISTS '{a}'@'localhost'\"; \
         rm -rf /srv/sites/{a}; userdel {a} 2>/dev/null; groupdel {a} 2>/dev/null; rm -f /var/spool/mail/{a}; true",
        a = layout.account
    );
    sh(&cleanup);
    let result = std::panic::catch_unwind(|| {
        let uid = choose_uid(ranges, &[]).unwrap();
        let account = create_account(&layout, uid).unwrap();
        assert_eq!(account, format!("account rs_tstep1 uid={uid} gid={uid}"));
        assert_eq!(create_account(&layout, uid), Err(ExecutorError::Collision));
        let other = SiteLayout::derive(&site("tstep2"));
        assert_eq!(
            create_account(&other, uid),
            Err(ExecutorError::Collision),
            "an id already in passwd is refused even for a free name"
        );
        create_directories(&layout).unwrap();
        assert_eq!(create_directories(&layout), Err(ExecutorError::Collision));
        assert_eq!(
            sh("stat -c '%a %U:%G %n' /srv/sites/rs_tstep1 /srv/sites/rs_tstep1/*"),
            "751 root:root /srv/sites/rs_tstep1\n755 root:root /srv/sites/rs_tstep1/errors\n750 rs_tstep1:nobody /srv/sites/rs_tstep1/html\n750 rs_tstep1:rs_tstep1 /srv/sites/rs_tstep1/logs\n750 rs_tstep1:rs_tstep1 /srv/sites/rs_tstep1/private\n750 rs_tstep1:rs_tstep1 /srv/sites/rs_tstep1/tmp"
        );
        assert_eq!(
            sh("stat -c '%a %U:%G' /srv/sites/rs_tstep1/errors/503.html"),
            "644 root:root"
        );
        let category = choose_category(ranges, &[]).unwrap();
        let labels = apply_labels(&layout, category).unwrap();
        assert_eq!(
            apply_labels(&layout, category),
            Err(ExecutorError::Collision)
        );
        let level = labels.rsplit("level=").next().unwrap().to_owned();
        // W277: every skeleton entry, labelled by descriptor (W274), carries
        // exactly what restorecon would give from the fcontext rules.
        let (content, rw) = ("httpd_sys_content_t", "httpd_sys_rw_content_t");
        for (entry, kind) in [
            ("", content),
            ("/errors", content),
            ("/errors/503.html", content),
            ("/html", content),
            ("/private", content),
            ("/tmp", rw),
            ("/logs", rw),
        ] {
            let path = format!("/srv/sites/rs_tstep1{entry}");
            assert_eq!(
                sh(&format!("stat -c %C {path}")),
                format!("system_u:object_r:{kind}:{level}"),
                "{path}"
            );
            assert_eq!(
                sh(&format!("matchpathcon -n {path}")),
                sh(&format!("stat -c %C {path}")),
                "{path} differs from matchpathcon"
            );
        }
        let units = install_php_units(&layout).unwrap();
        assert!(units.contains(&level), "{units}");
        assert_eq!(install_php_units(&layout), Err(ExecutorError::Collision));
        assert_eq!(
            sh(
                "systemctl is-active rustiron-site-php@rs_tstep1.socket rustiron-site-sandbox-check@rs_tstep1.timer"
            ),
            "active\nactive"
        );
        assert_eq!(
            sh("stat -c '%a %U:%G' /run/rustiron-sites/rs_tstep1.sock"),
            "660 root:nobody"
        );
        let (database, password) = create_database(&layout).unwrap();
        assert_eq!(database, "database rs_tstep1 user rs_tstep1@localhost");
        assert_eq!(password.len(), 48);
        assert_eq!(create_database(&layout), Err(ExecutorError::Collision));
        write_credentials(&layout, &password).unwrap();
        assert_eq!(
            write_credentials(&layout, &password),
            Err(ExecutorError::Collision)
        );
        assert_eq!(
            sh(
                "stat -c '%a %U:%G' /srv/sites/rs_tstep1/private/db.cnf; stat -c %C /srv/sites/rs_tstep1/private/db.cnf | cut -d: -f3-"
            ),
            format!("600 rs_tstep1:rs_tstep1\nhttpd_sys_content_t:{level}")
        );
        // The site's credentials reach only its own database.
        assert_eq!(
            sh(
                "mariadb --defaults-file=/srv/sites/rs_tstep1/private/db.cnf -N -e 'SHOW DATABASES' | grep -v information_schema"
            ),
            "rs_tstep1"
        );
        assert!(sh("mariadb --defaults-file=/srv/sites/rs_tstep1/private/db.cnf -N -e 'USE g0_site_a' 2>&1").contains("Access denied"));
        let recipes = std::path::Path::new("/var/lib/rustiron-s04-lab/recipes");
        let file = "wordpress-7.1.3.tar.gz";
        let marker = "$wp_version = '7.1.3';";
        let wrong = Sha256Digest::try_from("0".repeat(64)).unwrap();
        assert_eq!(
            unpack_recipe(&layout, recipes, file, &wrong, marker),
            Err(ExecutorError::StepFailed)
        );
        assert_eq!(sh("ls -A /srv/sites/rs_tstep1/html | wc -l"), "0");
        let pinned = Sha256Digest::try_from(
            "d2a09acb6a15e3b9c471d72557753c266d6f41a79ed19bfe04cbfe49e283b2a5".to_owned(),
        )
        .unwrap();
        let recipe = unpack_recipe(&layout, recipes, file, &pinned, marker).unwrap();
        assert!(
            recipe.starts_with("recipe wordpress-7.1.3.tar.gz sha256=d2a09acb"),
            "{recipe}"
        );
        assert_eq!(
            unpack_recipe(&layout, recipes, file, &pinned, marker),
            Err(ExecutorError::Collision)
        );
        assert_eq!(
            sh("find /srv/sites/rs_tstep1/html ! -user rs_tstep1 | wc -l"),
            "0"
        );
        assert_eq!(
            sh("stat -c %C /srv/sites/rs_tstep1/html/wp-login.php | cut -d: -f3-"),
            format!("httpd_sys_content_t:{level}")
        );
        assert_eq!(
            sh("stat -c '%a' /srv/sites/rs_tstep1/html/wp-login.php"),
            "644"
        );
        write_wp_config(&layout).unwrap();
        assert_eq!(write_wp_config(&layout), Err(ExecutorError::Collision));
        assert_eq!(
            sh(
                "stat -c '%a %U' /srv/sites/rs_tstep1/html/wp-config.php; stat -c %C /srv/sites/rs_tstep1/html/wp-config.php | cut -d: -f3-"
            ),
            format!("600 rs_tstep1\nhttpd_sys_content_t:{level}")
        );
        assert_eq!(
            sh(
                "grep -cE \"^define\\('[A-Z_]+', '[0-9a-f]{64}'\\);$\" /srv/sites/rs_tstep1/html/wp-config.php"
            ),
            "8"
        );
        assert_eq!(
            sh(&format!(
                "grep -c {password} /srv/sites/rs_tstep1/html/wp-config.php"
            )),
            "0",
            "credentials are not copied into wp-config.php"
        );
        let host = Hostname::try_from("tstep1.example.test".to_owned()).unwrap();
        let installed = install_wordpress(&layout, &host).unwrap();
        assert_eq!(
            installed,
            "installed http://tstep1.example.test admin=rustiron_admin"
        );
        assert_eq!(
            install_wordpress(&layout, &host),
            Err(ExecutorError::Collision),
            "the handover exists, so a second install is refused before any PHP runs"
        );
        assert_eq!(
            sh("stat -c '%a %U:%G' /srv/sites/rs_tstep1/private/rustiron-admin.txt"),
            "600 root:root"
        );
        assert_eq!(sh("ls -A /srv/sites/rs_tstep1/tmp | wc -l"), "0");
        assert_eq!(
            sh("mariadb -N -e 'SELECT user_login FROM rs_tstep1.wp_users'"),
            "rustiron_admin"
        );
        let secret =
            sh("awk '/^password/{print $2}' /srv/sites/rs_tstep1/private/rustiron-admin.txt");
        assert_eq!(secret.len(), 48);
        assert_eq!(
            sh(&format!(
                "grep -rl {secret} /srv/sites/rs_tstep1/html /srv/sites/rs_tstep1/tmp | wc -l"
            )),
            "0"
        );
        let pinned_list = Sha256Digest::try_from(
            "78ff5ec132f655e0ed8411984d985bd3bd58271f782745d20200e28a8e571671".to_owned(),
        )
        .unwrap();
        assert_eq!(
            read_pinned(recipes, "wordpress-7.1.3.md5.json", &wrong),
            Err(ExecutorError::StepFailed)
        );
        let checksums = read_pinned(recipes, "wordpress-7.1.3.md5.json", &pinned_list).unwrap();
        let verified = verify_site(&layout, &checksums, true).unwrap();
        assert!(
            verified.ends_with("core_files=3782 installed=true"),
            "{verified}"
        );
        // One edited core file fails verification.
        sh("printf '\\n' >> /srv/sites/rs_tstep1/html/wp-trackback.php");
        assert_eq!(
            verify_site(&layout, &checksums, true),
            Err(ExecutorError::StepFailed)
        );
        assert!(verified.contains(&level), "{verified}");
    });
    sh(&cleanup);
    assert!(result.is_ok());
    assert_eq!(sh("id rs_tstep1 2>&1 | grep -c 'no such user'"), "1");
}
