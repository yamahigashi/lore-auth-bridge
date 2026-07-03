//! Repository administration command implementations.

use std::path::Path;

use anyhow::{Result, anyhow};
use lore_auth_core::{
    model::{Resource, ResourceID},
    ports::{ResourceQuery, ResourceStore},
};

use crate::{RepoCommand, authctl_actor, core_error, open_env};

pub(crate) async fn run(config_path: &Path, db: Option<&Path>, command: RepoCommand) -> Result<()> {
    let env = open_env(config_path, db).await?;
    let audited = env.store.audited(authctl_actor());
    match command {
        RepoCommand::Add(args) => {
            let lore_repository_id = args.lore_repository_id;
            let resource = Resource {
                name: args.name,
                remote_url: args.remote,
                lore_repository_id: lore_repository_id.clone(),
                ..Resource::default()
            };
            audited.upsert(resource).await.map_err(core_error)?;
            let repo = env
                .store
                .get_by_resource_id(
                    &ResourceID::for_repository_id(&lore_repository_id)
                        .ok_or_else(|| anyhow!("lore_repository_id must not be empty"))?,
                )
                .await
                .map_err(core_error)?;
            println!("{}\t{}\t{}", repo.id, repo.name, repo.lore_repository_id);
        }
        RepoCommand::List => {
            for repo in env.store.list().await.map_err(core_error)? {
                println!(
                    "{}\t{}\t{}\t{}",
                    repo.id, repo.name, repo.lore_repository_id, repo.remote_url
                );
            }
        }
    }
    Ok(())
}
