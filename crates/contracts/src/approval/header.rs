//! W711 (pass 33, fix 4): the header that every signed plan and its grant
//! share, checked in one place. A verb's binding check compares its own
//! fields first, then calls `check_signed_header!` for the rest.

use crate::{Id, Timestamp};

use super::{ApprovalError, Sha256Digest};

/// The enrolled values that every signed plan and grant must name, and the
/// executor's reliable time.
pub(crate) struct Enrolled<'a> {
    pub host_id: &'a Id,
    pub host_epoch: &'a Id,
    pub profile_digest: &'a Sha256Digest,
    pub requester: &'a Id,
    pub issuer: &'a Id,
    pub signer_policy_epoch: &'a Id,
    pub now: Option<Timestamp>,
}

/// Compares the shared header of a plan and its grant:
///
/// - the grant names the plan by id and by digest;
/// - the plan and the grant both name the enrolled host, epoch, profile,
///   and requester;
/// - the grant names the enrolled issuer and signer-policy epoch;
/// - the grant's validity lies inside the plan's;
/// - the executor time is known and inside the grant's validity.
///
/// A difference is `BindingMismatch`, unknown time `ClockUncertain`, and a
/// time outside the grant `OutsideValidity`, in that order.
macro_rules! check_signed_header {
    ($plan:expr, $grant:expr, $enrolled:expr) => {{
        let (p, g, e) = (&$plan.record, &$grant.record, $enrolled);
        $crate::approval::header::check(
            g.plan_digest == $plan.digest()
                && g.plan_id == p.plan_id
                && p.host_id == *e.host_id
                && g.host_id == *e.host_id
                && p.host_epoch == *e.host_epoch
                && g.host_epoch == *e.host_epoch
                && p.profile_digest == *e.profile_digest
                && g.profile_digest == *e.profile_digest
                && p.requester == *e.requester
                && g.requester == *e.requester
                && g.issuer == *e.issuer
                && g.signer_policy_epoch == *e.signer_policy_epoch,
            (p.valid_from, p.expires_at),
            (g.valid_from, g.expires_at),
            e.now,
        )
    }};
}

/// The end of `check_signed_header!`: the header result, then the
/// validity windows and the time.
pub(crate) fn check(
    header_matches: bool,
    (plan_from, plan_until): (Timestamp, Timestamp),
    (grant_from, grant_until): (Timestamp, Timestamp),
    now: Option<Timestamp>,
) -> Result<(), ApprovalError> {
    if !header_matches || grant_from.get() < plan_from.get() || grant_until.get() > plan_until.get()
    {
        return Err(ApprovalError::BindingMismatch);
    }
    let now = now.ok_or(ApprovalError::ClockUncertain)?;
    if now.get() < grant_from.get() || now.get() >= grant_until.get() {
        return Err(ApprovalError::OutsideValidity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check;
    use crate::{Timestamp, approval::ApprovalError};

    fn at(seconds: u64) -> Timestamp {
        Timestamp::try_from(seconds).unwrap()
    }

    /// The order and the edges: a header or window difference first, then
    /// unknown time, then time outside the grant (its end is exclusive).
    #[test]
    fn the_shared_header_refuses_in_a_fixed_order() {
        let plan = (at(100), at(200));
        let grant = (at(110), at(190));
        assert_eq!(check(true, plan, grant, Some(at(110))), Ok(()));
        assert_eq!(
            check(false, plan, grant, None),
            Err(ApprovalError::BindingMismatch)
        );
        assert_eq!(
            check(true, plan, (at(99), at(190)), Some(at(150))),
            Err(ApprovalError::BindingMismatch)
        );
        assert_eq!(
            check(true, plan, (at(110), at(201)), Some(at(150))),
            Err(ApprovalError::BindingMismatch)
        );
        assert_eq!(check(true, plan, plan, Some(at(150))), Ok(()));
        assert_eq!(
            check(true, plan, grant, None),
            Err(ApprovalError::ClockUncertain)
        );
        assert_eq!(
            check(true, plan, grant, Some(at(109))),
            Err(ApprovalError::OutsideValidity)
        );
        assert_eq!(
            check(true, plan, grant, Some(at(190))),
            Err(ApprovalError::OutsideValidity)
        );
    }
}
