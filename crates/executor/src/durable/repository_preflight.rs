//! Resolve the fixed product worker credential sources before any launch.

use std::{
    os::fd::OwnedFd,
    path::{Path, PathBuf},
};

use rustiron_contracts::approval::{
    MAX_PRODUCT_BACKUP_CA_BYTES, MAX_PRODUCT_BACKUP_POLICY_BYTES, MAX_PRODUCT_BACKUP_SECRET_BYTES,
    ProductBackupSite,
};

use crate::{ExecutorError, TrustAnchor, files, layout, policy::PRODUCT_BACKUP_PROJECTION_FILE};

const CA_FILE: &str = "backup-ca.pem";

/// The enrolled key pair a store job receives in its one `aws` slot. The
/// worker cannot tell them apart; the launcher chooses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StoreIdentity {
    /// The read-only fetch principal: identity checks, listings, `check`,
    /// and the manifest dump (design steps 2, 7, 8 and 10).
    Fetch,
    /// The capture principal: `lock` (W334 design steps 3 and 9), which
    /// reads the bucket lock settings and object retention, and the snapshot
    /// write `backup` (step 6, W356).
    Capture,
}

pub(crate) fn credential_properties(
    anchor: &TrustAnchor,
    policy_directory: &OwnedFd,
    site: &ProductBackupSite<'_>,
    identity: StoreIdentity,
) -> Result<[String; 4], ExecutorError> {
    let product_root = Path::new(layout::product::POLICY_DIR);
    let credential_suffix = Path::new(layout::product::JOB_CREDENTIALS_DIR)
        .strip_prefix(product_root)
        .map_err(|_| ExecutorError::Unavailable)?;
    let credential_root = anchor.policy_dir.join(credential_suffix);
    let enrolled = match identity {
        StoreIdentity::Fetch => site.fetch_credential(),
        StoreIdentity::Capture => site.capture_credential(),
    };
    let key_pair = credential_root.join(enrolled.relative_path());
    let password = credential_root.join(site.password_path());
    let site_directory = key_pair.parent().ok_or(ExecutorError::Unavailable)?;
    if password.parent() != Some(site_directory) {
        return Err(ExecutorError::AccessDenied);
    }
    let credentials = files::open_trusted_directory(site_directory, anchor.owner_uid)?;

    Ok([
        credential(
            "destination",
            anchor.policy_dir.join(PRODUCT_BACKUP_PROJECTION_FILE),
            policy_directory,
            anchor.owner_uid,
            MAX_PRODUCT_BACKUP_POLICY_BYTES,
        )?,
        credential(
            "ca",
            anchor.policy_dir.join(CA_FILE),
            policy_directory,
            anchor.owner_uid,
            MAX_PRODUCT_BACKUP_CA_BYTES,
        )?,
        credential(
            "aws",
            key_pair,
            &credentials,
            anchor.owner_uid,
            MAX_PRODUCT_BACKUP_SECRET_BYTES,
        )?,
        credential(
            "password",
            password,
            &credentials,
            anchor.owner_uid,
            MAX_PRODUCT_BACKUP_SECRET_BYTES,
        )?,
    ])
}

fn credential(
    id: &str,
    path: PathBuf,
    directory: &OwnedFd,
    owner: u32,
    limit: usize,
) -> Result<String, ExecutorError> {
    let leaf = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ExecutorError::AccessDenied)?;
    let text = path.to_str().ok_or(ExecutorError::AccessDenied)?;
    // Keep systemd specifiers and control bytes out of unit properties.
    if !text
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte))
    {
        return Err(ExecutorError::AccessDenied);
    }
    let stat = files::private_regular_stat(directory, leaf, owner)?;
    if !(1..=limit as i64).contains(&stat.st_size) {
        return Err(ExecutorError::Unavailable);
    }
    Ok(format!("LoadCredential={id}:{text}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{hex, private_dir, private_file};
    use rustiron_contracts::approval::{ProductBackupPolicy, SiteId};

    /// Builds the fixture policy directory, resolves `blog9`, and returns
    /// the properties for `identity` with the site directory path.
    fn properties_for(
        identity: StoreIdentity,
    ) -> (Result<[String; 4], ExecutorError>, PathBuf, PathBuf) {
        let mut random = [0; 16];
        rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty()).unwrap();
        let root = std::env::temp_dir().join(format!("ri-product-credentials-{}", hex(&random)));
        let mut anchor = TrustAnchor::host();
        anchor.owner_uid = rustix::process::getuid().as_raw();
        anchor.policy_dir = root.clone();
        let site_directory = root.join("credentials/sites/rs_blog9");
        private_dir(&root);
        private_dir(&site_directory);
        let projection = include_bytes!("../../../../docs/validation/S10-W307/projection.json");
        private_file(&root.join("backup-destination.json"), projection);
        private_file(&root.join("backup-ca.pem"), b"synthetic CA");
        private_file(&site_directory.join("fetch-aws"), b"synthetic fetch");
        private_file(&site_directory.join("aws"), b"synthetic upload canary");
        private_file(&site_directory.join("repo.password"), b"synthetic password");
        let directory = files::open_trusted_directory(&root, anchor.owner_uid).unwrap();
        let policy = ProductBackupPolicy::decode(projection).unwrap();
        let site = policy
            .resolve_site(&SiteId::try_from("blog9".to_owned()).unwrap())
            .unwrap();
        let properties = credential_properties(&anchor, &directory, &site, identity);
        std::fs::remove_dir_all(&root).unwrap();
        (properties, root, site_directory)
    }

    #[test]
    fn preflight_uses_the_fetch_slot_and_fixed_policy_leaves() {
        let (properties, root, site_directory) = properties_for(StoreIdentity::Fetch);
        assert_eq!(
            properties.unwrap(),
            [
                format!(
                    "LoadCredential=destination:{}/backup-destination.json",
                    root.display()
                ),
                format!("LoadCredential=ca:{}/backup-ca.pem", root.display()),
                format!("LoadCredential=aws:{}/fetch-aws", site_directory.display()),
                format!(
                    "LoadCredential=password:{}/repo.password",
                    site_directory.display()
                ),
            ]
        );
    }

    #[test]
    fn the_lock_job_gets_the_capture_slot_with_the_same_other_leaves() {
        let (properties, root, site_directory) = properties_for(StoreIdentity::Capture);
        assert_eq!(
            properties.unwrap(),
            [
                format!(
                    "LoadCredential=destination:{}/backup-destination.json",
                    root.display()
                ),
                format!("LoadCredential=ca:{}/backup-ca.pem", root.display()),
                format!("LoadCredential=aws:{}/aws", site_directory.display()),
                format!(
                    "LoadCredential=password:{}/repo.password",
                    site_directory.display()
                ),
            ]
        );
    }
}
