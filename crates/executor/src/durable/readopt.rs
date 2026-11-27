//! W372 (D-030 option C): the signed `site_readopt` verb.
//!
//! Admission order (RE-ADOPTION): closed binding, signature and time; the
//! journal facts before intent; the intent `verifying`, which consumes the
//! grant; one read-only observation (the executor's own reads plus the admin
//! helper's `readopt_observe`); the executor's decision; one transaction
//! that records `adopted` or `refused`. Nothing on the host is created,
//! changed or removed, and nothing is compensated. A crash after intent
//! leaves the row `verifying`; `reconcile` repeats the observation.

use rustiron_contracts::{
    Id,
    approval::{ReadoptForm, ReadoptPlan, SiteId},
};
use rustiron_journal::{
    Admitted, ProvisionStep, ReadoptOutcome, ReadoptState, Readoption, ReadoptionIntent,
    SiteAdoption,
};

use super::{Executor, Fault, grant_digest, ols_resource, signed_inputs};
use crate::{
    AdmissionRequest, ExecutorError,
    admin_helper::{self, AdminRequest, AdminStep, Reply},
    ols, policy,
    provision::{self, SiteLayout},
    quota::QuotaLimits,
    readopt::{
        self, GenerationInput, HostGenerationFacts, HostSiteFacts, Rule, SiteInput, SiteRules,
    },
    verified_readopt,
};

/// Test-only replacement of what the host shows the next observation
/// (`fault-injection` builds only).
#[derive(Clone, Debug)]
pub enum ReadoptObservation {
    /// The site form's reads.
    Site(Box<SiteInput>),
    /// The generation form's reads.
    Generation(Box<GenerationInput>),
}

/// What one observation decided, before it is journaled.
struct Decision {
    facts: String,
    verdict: Result<Adopted, Rule>,
}

enum Adopted {
    Site(SiteAdoption),
    Generation(Id, rustiron_contracts::approval::Sha256Digest),
}

impl Executor {
    /// Admits one signed `site_readopt`, records it `verifying`, observes
    /// and records the outcome. An exact verified repeat returns stored
    /// status and observes nothing. A refusal after intent is returned as
    /// its code (`READOPT_MISMATCH` or `OLS_DRIFT`) with the row `refused`.
    pub fn readopt(
        &mut self,
        request: &AdmissionRequest<'_>,
    ) -> Result<Admitted<Readoption>, ExecutorError> {
        let (plan, grant, enrolled) = verified_readopt(&self.anchor, request)?;
        self.check_enrolled_identity(&enrolled)?;
        let digests = (plan.digest(), grant_digest(grant.as_bytes()));
        if let Some(existing) = self.journal.readoption_status(&request.operation_id)? {
            return if existing.intent.idempotency_key == request.idempotency_key
                && existing.intent.plan_digest == digests.0
                && existing.intent.grant_digest == digests.1
            {
                Ok(Admitted::Existing(existing))
            } else {
                Err(ExecutorError::ReplayDenied)
            };
        }
        self.readopt_preconditions(&plan)?;
        let intent = ReadoptionIntent {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            grant_id: grant.grant_id().clone(),
            nonce: grant.nonce().clone(),
            plan_digest: digests.0,
            grant_digest: digests.1,
            host_id: enrolled.host_id.clone(),
            host_epoch: enrolled.host_epoch,
            form: plan.form(),
            site: plan
                .site()
                .map(|(site, hostname, _)| (site.clone(), hostname.clone())),
            previous_epoch: plan.previous_epoch().clone(),
            evidence_sha256: plan.evidence_sha256().clone(),
            expires_at: grant.expires_at(),
            plan: String::from_utf8(plan.as_bytes().to_vec())
                .map_err(|_| ExecutorError::InvalidRequest)?,
        };
        let now = request.now.ok_or(ExecutorError::TimeDenied)?;
        match self.admit(signed_inputs(request)?, |journal| {
            journal.record_readoption(&intent, now)
        })? {
            Admitted::Existing(existing) => return Ok(Admitted::Existing(existing)),
            Admitted::New(_) => {}
        }
        self.fault(Fault::AfterReadoptIntent)?;
        self.verify_readoption(&request.operation_id)
            .map(Admitted::New)
    }

    /// Re-adoption status only.
    pub fn readoption_status(
        &self,
        operation_id: &Id,
    ) -> Result<Option<Readoption>, ExecutorError> {
        Ok(self.journal.readoption_status(operation_id)?)
    }

    /// `reconcile` of a re-adoption: a `verifying` row repeats the complete
    /// read-only observation and records its outcome; a settled row is
    /// returned as stored. Never `adopted` without a complete observation.
    pub fn reconcile_readoption(&mut self, operation_id: &Id) -> Result<Readoption, ExecutorError> {
        let row = self
            .journal
            .readoption_status(operation_id)?
            .ok_or(ExecutorError::NotAdmitted)?;
        if row.state != ReadoptState::Verifying {
            return Ok(row);
        }
        self.verify_readoption(operation_id)
    }

    /// Test-only: the next observation returns `observation` instead of
    /// reading the host.
    #[cfg(feature = "fault-injection")]
    pub fn inject_readopt_observation(&mut self, observation: ReadoptObservation) {
        self.readopt_observation = Some(observation);
    }

    /// The journal facts before intent (RE-ADOPTION, pre-intent checks).
    fn readopt_preconditions(&self, plan: &ReadoptPlan) -> Result<(), ExecutorError> {
        let ejected = self.journal.ejected_sites()?;
        let marker = |site: &SiteId| ols::has_eject_marker(&site.account_name());
        if let Some((site, _, _)) = plan.site() {
            if self.journal.provision_for_site(site)?.is_some() || marker(site)? {
                return Err(ExecutorError::PreconditionChanged);
            }
            return Ok(());
        }
        let (_, _, sites) = plan.generation().ok_or(ExecutorError::InvalidRequest)?;
        if self.journal.resource_operations(&ols_resource()?)? > 0
            || self.journal.ols_adoption()?.is_some()
        {
            return Err(ExecutorError::PreconditionChanged);
        }
        for site in sites {
            let owned = self
                .journal
                .provision_for_site(site)?
                .is_some_and(|provision| provision.state.is_owned());
            if !owned || ejected.contains(site) || marker(site)? {
                return Err(ExecutorError::PreconditionChanged);
            }
        }
        Ok(())
    }

    /// Steps 5 to 7: observe, decide, record. A missing helper, or a lost
    /// helper reply, leaves the row `verifying` for `reconcile`.
    fn verify_readoption(&mut self, operation_id: &Id) -> Result<Readoption, ExecutorError> {
        let row = self
            .journal
            .readoption_status(operation_id)?
            .filter(|row| row.state == ReadoptState::Verifying)
            .ok_or(ExecutorError::NotAdmitted)?;
        let plan = ReadoptPlan::decode(row.intent.plan.as_bytes())
            .map_err(|_| ExecutorError::Unavailable)?;
        let enrolled = self.readopt_policy()?;
        let decision = match plan.form() {
            ReadoptForm::Site => self.decide_site(operation_id, &plan, &enrolled)?,
            ReadoptForm::Generation => self.decide_generation(operation_id, &plan, &enrolled)?,
        };
        self.fault(Fault::AfterReadoptObservation)?;
        let floor = plan
            .allocation_floor()
            .map(|floor| (floor.uid(), floor.category()));
        match decision.verdict {
            Ok(adopted) => {
                let (site, generation) = match adopted {
                    Adopted::Site(site) => (Some(site), None),
                    Adopted::Generation(id, digest) => (None, Some((id, digest))),
                };
                Ok(self.journal.finish_readoption(
                    operation_id,
                    ReadoptOutcome::Adopted {
                        facts: &decision.facts,
                        site,
                        generation,
                        floor,
                    },
                )?)
            }
            Err(rule) => {
                let error = rule.error();
                eprintln!(
                    "{{\"scope\":\"site_readopt\",\"refused\":\"{}\",\"rule\":\"{}\"}}",
                    error.code(),
                    rule.name()
                );
                self.journal.finish_readoption(
                    operation_id,
                    ReadoptOutcome::Refused {
                        facts: &decision.facts,
                        code: error.code(),
                        rule: rule.name(),
                    },
                )?;
                Err(error)
            }
        }
    }

    fn readopt_policy(&self) -> Result<policy::Policy, ExecutorError> {
        let owner = self.anchor.owner_uid;
        Ok(policy::load(
            &crate::files::open_trusted_directory(&self.anchor.policy_dir, owner)?,
            owner,
        )?
        .policy)
    }

    /// UIDs and categories the current journal records: every Account and
    /// Labels step and every adopted site.
    fn recorded_allocations(&self) -> Result<(Vec<u32>, Vec<u32>), ExecutorError> {
        let mut uids = provision::recorded_numbers(
            &self.journal.recorded_resources(ProvisionStep::Account)?,
            "uid=",
        );
        let mut categories = provision::recorded_numbers(
            &self.journal.recorded_resources(ProvisionStep::Labels)?,
            "level=s0:c",
        );
        let (adopted_uids, adopted_categories) = self.journal.adopted_allocations()?;
        uids.extend(adopted_uids);
        categories.extend(adopted_categories);
        Ok((uids, categories))
    }

    fn decide_site(
        &mut self,
        operation_id: &Id,
        plan: &ReadoptPlan,
        enrolled: &policy::Policy,
    ) -> Result<Decision, ExecutorError> {
        let (site, _, limits) = plan.site().ok_or(ExecutorError::Unavailable)?;
        let provisioning = enrolled
            .provisioning
            .as_ref()
            .ok_or(ExecutorError::Unavailable)?;
        let cap = provisioning.quota.ok_or(ExecutorError::Unavailable)?;
        let quota = QuotaLimits::from(limits);
        if !quota.within(cap) {
            return Err(ExecutorError::BindingDenied);
        }
        let layout = SiteLayout::derive(site);
        let Some(input) = self.site_input(operation_id, &layout)? else {
            return Ok(Decision {
                facts: "{\"observation\":\"refused\"}".to_owned(),
                verdict: Err(Rule::Observation),
            });
        };
        let (uids, categories) = self.recorded_allocations()?;
        let verdict = readopt::judge_site(
            &layout,
            &input,
            &SiteRules {
                uid_range: (provisioning.uid_min, provisioning.uid_max),
                category_range: (provisioning.category_min, provisioning.category_max),
                quota,
                recorded_uids: &uids,
                recorded_categories: &categories,
            },
        );
        let facts = readopt::site_summary(&layout, &input, &verdict);
        Ok(Decision {
            facts,
            verdict: verdict.map(|verified| {
                Adopted::Site(SiteAdoption {
                    uid: verified.uid,
                    category: verified.category,
                    quota_kib: quota.block_hard_kib,
                    quota_inodes: quota.inode_hard,
                })
            }),
        })
    }

    /// The site form's reads: the executor's own and the helper's. `None`
    /// is a helper refusal or an unreadable reply (a refusal, recorded).
    fn site_input(
        &mut self,
        operation_id: &Id,
        layout: &SiteLayout,
    ) -> Result<Option<SiteInput>, ExecutorError> {
        #[cfg(feature = "fault-injection")]
        if let Some(ReadoptObservation::Site(input)) = self.readopt_observation.take() {
            return Ok(Some(*input));
        }
        let host = match self.helper_observation(operation_id)? {
            HelperFacts::Local => readopt::observe_host_site(layout),
            HelperFacts::Payload(payload) => match HostSiteFacts::decode(&payload) {
                Some(facts) => facts,
                None => return Ok(None),
            },
            HelperFacts::Refused => return Ok(None),
        };
        let (passwd, group, fcontexts) = readopt::read_site_inputs()?;
        Ok(Some(SiteInput {
            passwd,
            group,
            fcontexts,
            host,
        }))
    }

    fn decide_generation(
        &mut self,
        operation_id: &Id,
        plan: &ReadoptPlan,
        enrolled: &policy::Policy,
    ) -> Result<Decision, ExecutorError> {
        let (generation, digest, listed) = plan.generation().ok_or(ExecutorError::Unavailable)?;
        let ols_policy = enrolled.ols.clone().ok_or(ExecutorError::Unavailable)?;
        let mut cached = ols_policy.lscache.clone();
        cached.extend(self.journal.page_cache_sites()?);
        let mut sites = Vec::new();
        for site in listed {
            let provision = self
                .journal
                .provision_for_site(site)?
                .filter(|provision| provision.state.is_owned());
            let Some(provision) = provision else {
                // Pre-intent checked ownership, and `verifying` blocks every
                // change since; a missing owner is still never adopted.
                return Ok(Decision {
                    facts: "{\"owned\":false}".to_owned(),
                    verdict: Err(Rule::Render),
                });
            };
            let proxy = self.journal.proxy_facts(&provision.intent.operation_id)?;
            sites.push(ols::ServedSite {
                account: SiteLayout::derive(site).account,
                alias_hostname: None,
                hostname: provision.intent.hostname,
                ejected: false,
                static_ejected: false,
                lscache: cached.contains(site),
                tls_alias: None,
                tls: self
                    .journal
                    .installed_certificate(site)?
                    .map(|(sha, _)| sha),
                acme: ols::acme_webroot_present(&SiteLayout::derive(site).account),
                proxy,
            });
        }
        sites.sort_by(|a, b| a.account.cmp(&b.account));
        let rendered = ols::render_with_tls(
            &ols_policy.listener,
            &ols_policy.address,
            ols_policy.tls_address.as_deref(),
            &ols_policy.adopted,
            &sites,
        );
        let input = self.generation_input(operation_id, &ols_policy, &sites)?;
        let verdict = readopt::judge_generation(&input, (generation, digest), &rendered);
        let facts = readopt::generation_summary(&input, &rendered, &verdict);
        Ok(Decision {
            facts,
            verdict: verdict.map(|()| Adopted::Generation(generation.clone(), digest.clone())),
        })
    }

    /// The generation form's reads: `current` and its stored files in this
    /// process (an unreadable include is no `current`), the server, unit
    /// and probe facts from the helper.
    fn generation_input(
        &mut self,
        operation_id: &Id,
        ols_policy: &policy::OlsPolicy,
        sites: &[ols::ServedSite],
    ) -> Result<GenerationInput, ExecutorError> {
        #[cfg(feature = "fault-injection")]
        if let Some(ReadoptObservation::Generation(input)) = self.readopt_observation.take() {
            return Ok(*input);
        }
        let host = match self.helper_observation(operation_id)? {
            HelperFacts::Local => readopt::observe_host_generation(ols_policy, sites).ok(),
            HelperFacts::Payload(payload) => HostGenerationFacts::decode(&payload),
            HelperFacts::Refused => None,
        };
        let include = ols::open_include();
        let current = include
            .as_ref()
            .ok()
            .and_then(|include| ols::observe_current(include).ok())
            .flatten();
        let stored = match (&include, &current) {
            (Ok(include), Some((id, _))) => ols::stored_generation(include, id).ok(),
            _ => None,
        };
        Ok(GenerationInput {
            current,
            stored,
            host,
        })
    }

    /// One `readopt_observe` request, or the in-process reads without a
    /// helper (D-016 lab mode). An absent helper or a lost reply is an
    /// error and the row stays `verifying`.
    fn helper_observation(&self, operation_id: &Id) -> Result<HelperFacts, ExecutorError> {
        let Some(socket) = self.anchor.admin_socket.clone() else {
            return Ok(HelperFacts::Local);
        };
        admin_helper::reach(
            &socket,
            admin_helper::REACH_ATTEMPTS,
            admin_helper::REACH_PAUSE,
        )?;
        match admin_helper::request(
            &socket,
            &AdminRequest {
                operation_id: operation_id.clone(),
                step: AdminStep::ReadoptObserve,
            },
        )? {
            Reply::Done(Some(payload)) => Ok(HelperFacts::Payload(payload)),
            Reply::Refused(ExecutorError::HelperUnreachable) => {
                Err(ExecutorError::HelperUnreachable)
            }
            Reply::Done(None) | Reply::Refused(_) => Ok(HelperFacts::Refused),
        }
    }

    /// W372 precondition of `site_provision`: an existing account or group
    /// of the derived name, or an existing site root, is `PROVISION_COLLISION`
    /// before intent. The account files are read here; the site root is
    /// asked of the helper when one is enrolled.
    pub(crate) fn provision_collision(&self, layout: &SiteLayout) -> Result<(), ExecutorError> {
        let (passwd, group) = (
            provision::read_etc("passwd")?,
            provision::read_etc("group")?,
        );
        readopt::provision_collision(&passwd, &group, &layout.account, false)?;
        let site = layout
            .account
            .strip_prefix("rs_")
            .and_then(|site| SiteId::try_from(site.to_owned()).ok())
            .ok_or(ExecutorError::Unavailable)?;
        let present = match self.anchor.admin_socket.as_deref() {
            Some(socket) => admin_helper::site_root_present(socket, &site)?,
            None => readopt::site_root_present(layout),
        };
        readopt::provision_collision(&passwd, &group, &layout.account, present)
    }
}

enum HelperFacts {
    /// No helper: read in this process.
    Local,
    /// The helper's reply payload.
    Payload(String),
    /// The helper refused or replied without facts.
    Refused,
}
