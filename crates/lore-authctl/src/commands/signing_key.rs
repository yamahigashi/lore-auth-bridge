//! Signing key command implementations.

use std::{path::Path, sync::Arc};

use anyhow::Result;
use lore_auth_adapters::rs256;
use lore_auth_core::ports::SigningKeyAdmin;

use crate::{SigningKeyCommand, authctl_actor, core_error, open_env};

pub(crate) async fn run(
    config_path: &Path,
    db: Option<&Path>,
    command: SigningKeyCommand,
) -> Result<()> {
    let env = open_env(config_path, db).await?;
    let audited = Arc::new(env.store.audited(authctl_actor()));
    let keys = rs256::SigningKeyAdmin::new(&env.cfg.jwt.signing_key_dir, audited);
    match command {
        SigningKeyCommand::Generate(args) => {
            let key = keys
                .generate_active_key(&args.kid, &args.alg, args.bits)
                .await
                .map_err(core_error)?;
            println!(
                "kid: {}\nprivate_key: {}\nstatus: {}",
                key.kid, key.private_key_path, key.status
            );
        }
        SigningKeyCommand::List => {
            for key in keys.list_keys().await.map_err(core_error)? {
                println!(
                    "{}\t{}\t{}\t{}",
                    key.kid, key.alg, key.status, key.private_key_path
                );
            }
        }
    }
    Ok(())
}
