//! W594 (P23, D-098): operator-visible blast-radius envelopes and budget checks.

use rustiron_contracts::approval::{
    ALL_SITE_OLS_IMPACT_EXPLANATION, AuthorityBudgetReport, AuthorityUsage, BlastRadiusLimits,
    EnvelopeRefusal, ImpactScope, check_envelope_budget, envelope_for_plan,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn load_fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
}

#[test]
fn ols_activation_and_eject_explain_all_site_ols_impact() {
    for (file, verb) in [
        ("ols-plan.json", "config_activate"),
        ("eject-plan.json", "site_eject"),
    ] {
        let env = envelope_for_plan(&load_fixture(file)).expect(file);
        assert_eq!(env.verb, verb);
        assert_eq!(env.scope, ImpactScope::AllServedSitesOlsReload);
        assert!(env.all_served_sites);
        assert_eq!(env.ols_reloads, 1);
        assert_eq!(env.compensation_reloads, 1);
        assert_eq!(
            env.all_site_ols_impact.as_deref(),
            Some(ALL_SITE_OLS_IMPACT_EXPLANATION)
        );
    }
}

#[test]
fn non_ols_plans_report_zero_ols_reloads_and_exact_budgets() {
    let site = envelope_for_plan(&load_fixture("site-plan.json")).unwrap();
    assert_eq!(site.verb, "site_provision");
    assert_eq!(site.scope, ImpactScope::SingleSite);
    assert!(!site.all_served_sites);
    assert_eq!(site.ols_reloads, 0);
    assert_eq!(site.all_site_ols_impact, None);

    let dns = envelope_for_plan(&load_fixture("dns-import-plan.json")).unwrap();
    assert_eq!(dns.verb, "dns_zone_import");
    assert_eq!(dns.scope, ImpactScope::SingleZoneDns);
    assert_eq!(dns.ols_reloads, 0);
    assert!(dns.max_changes >= 1);

    let update = envelope_for_plan(&load_fixture("update-plan.json")).unwrap();
    assert_eq!(update.verb, "site_update");
    assert_eq!(update.scope, ImpactScope::SingleSite);
    assert!(update.max_changes >= 1);
    assert_eq!(update.ols_reloads, 0);

    let proxy = envelope_for_plan(&load_fixture("proxy-site-plan.json")).unwrap();
    assert_eq!(proxy.verb, "proxy_site_provision");
    assert_eq!(proxy.scope, ImpactScope::SingleSite);
    assert_eq!(proxy.ols_reloads, 0);

    assert_eq!(envelope_for_plan(b"{}"), None);
    assert_eq!(envelope_for_plan(b"not json"), None);
}

#[test]
fn budget_checks_refuse_over_budget_and_report_remaining_authority() {
    let limits = BlastRadiusLimits {
        window_seconds: 3600,
        max_admissions_per_window: 5,
        max_ols_reloads_per_window: 2,
        max_served_sites_per_activation: 4,
        max_total_admissions: Some(10),
        max_total_ols_reloads: Some(3),
    };
    assert!(limits.valid());

    let ols = envelope_for_plan(&load_fixture("ols-plan.json")).unwrap();
    let site = envelope_for_plan(&load_fixture("site-plan.json")).unwrap();

    let mut usage = AuthorityUsage {
        total_admissions: 2,
        total_ols_reloads: 1,
        recent_admissions: 2,
        recent_ols_reloads: 1,
        served_sites: 2,
    };
    assert_eq!(check_envelope_budget(&limits, &ols, &usage), Ok(()));

    let report = AuthorityBudgetReport::build(Some(limits.clone()), usage.clone());
    assert!(report.enrolled);
    let rem = report.remaining.unwrap();
    assert_eq!(rem.recent_admissions, 3);
    assert_eq!(rem.recent_ols_reloads, 1);
    assert_eq!(rem.total_admissions, Some(8));
    assert_eq!(rem.total_ols_reloads, Some(2));

    // Exhaust rolling OLS reload budget: OLS reload refused, non-OLS site provision still allowed.
    usage.recent_ols_reloads = 2;
    assert_eq!(
        check_envelope_budget(&limits, &ols, &usage),
        Err(EnvelopeRefusal::OlsReloadWindowExhausted)
    );
    assert_eq!(check_envelope_budget(&limits, &site, &usage), Ok(()));

    // Exhaust hard epoch OLS reload cap.
    usage.recent_ols_reloads = 0;
    usage.total_ols_reloads = 3;
    assert_eq!(
        check_envelope_budget(&limits, &ols, &usage),
        Err(EnvelopeRefusal::OlsReloadTotalExhausted)
    );

    // Exhaust admission window.
    usage.total_ols_reloads = 0;
    usage.recent_admissions = 5;
    assert_eq!(
        check_envelope_budget(&limits, &site, &usage),
        Err(EnvelopeRefusal::AdmissionWindowExhausted)
    );

    // Exhaust hard epoch admission cap.
    usage.recent_admissions = 0;
    usage.total_admissions = 10;
    assert_eq!(
        check_envelope_budget(&limits, &site, &usage),
        Err(EnvelopeRefusal::AdmissionTotalExhausted)
    );

    // Exceed max_served_sites_per_activation.
    let mut small_cap = limits;
    small_cap.max_served_sites_per_activation = 1;
    let mut big_ols = ols;
    big_ols.sites_named = 2;
    assert_eq!(
        check_envelope_budget(&small_cap, &big_ols, &AuthorityUsage::default()),
        Err(EnvelopeRefusal::TooManyServedSites)
    );
}

#[test]
fn invalid_blast_radius_limits_are_refused() {
    let mut bad = BlastRadiusLimits {
        window_seconds: 59,
        max_admissions_per_window: 5,
        max_ols_reloads_per_window: 2,
        max_served_sites_per_activation: 4,
        max_total_admissions: None,
        max_total_ols_reloads: None,
    };
    assert!(!bad.valid());
    bad.window_seconds = 3600;
    bad.max_ols_reloads_per_window = 0;
    assert!(!bad.valid());
    bad.max_ols_reloads_per_window = 2;
    bad.max_served_sites_per_activation = 33;
    assert!(!bad.valid());
    bad.max_served_sites_per_activation = 4;
    bad.max_total_admissions = Some(0);
    assert!(!bad.valid());
}
