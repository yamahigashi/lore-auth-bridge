//! Grant administration command implementations.

use std::path::Path;

use anyhow::Result;
use lore_auth_core::ports::{GrantAdmin, GrantQuery};

use crate::{GrantCommand, authctl_actor, core_error, open_env, resolve_grant_subject};

pub(crate) async fn run(
    config_path: &Path,
    db: Option<&Path>,
    command: GrantCommand,
) -> Result<()> {
    let env = open_env(config_path, db).await?;
    let grants = env.store.audited(authctl_actor());
    match command {
        GrantCommand::Add(args) => {
            let (subject_type, subject_id) = resolve_grant_subject(&args.subject)?;
            let grant = grants
                .add_grant(&subject_type, &subject_id, &args.repo, &args.role)
                .await
                .map_err(core_error)?;
            println!(
                "{}\t{}:{}\t{}",
                grant.id, grant.subject_type, grant.subject_id, grant.role
            );
        }
        GrantCommand::Remove(args) => {
            let (subject_type, subject_id) = resolve_grant_subject(&args.subject)?;
            grants
                .remove_grant(&subject_type, &subject_id, &args.repo, &args.role)
                .await
                .map_err(core_error)?;
            println!("removed");
        }
        GrantCommand::List(args) => {
            let repo = args.repo.unwrap_or_default();
            for grant in env.store.list_grants(&repo).await.map_err(core_error)? {
                println!(
                    "{}\t{}:{}\t{}\t{}",
                    grant.id, grant.subject_type, grant.subject_id, grant.repository_id, grant.role
                );
            }
        }
    }
    Ok(())
}
