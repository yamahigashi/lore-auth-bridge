//! Authorization check command implementation.

use std::path::Path;

use anyhow::{Context, Result};
use lore_auth_core::ports::ResourceQuery;

use crate::{CheckArgs, build_authorization_policy, core_error, open_env};

pub(crate) async fn run(config_path: &Path, db: Option<&Path>, args: CheckArgs) -> Result<()> {
    let env = open_env(config_path, db).await?;
    let user = env
        .store
        .resolve_user(&args.user)
        .await
        .map_err(core_error)
        .with_context(|| format!("resolve user {:?}", args.user))?;
    let repo = env
        .store
        .get_by_name(&args.repo)
        .await
        .map_err(core_error)
        .with_context(|| format!("resolve repo {:?}", args.repo))?;
    let authz = build_authorization_policy(&env)?;
    let allowed = authz
        .can_access(&user.id, &repo.resource_id, &args.action)
        .await
        .map_err(core_error)?;
    if allowed {
        println!("allow");
    } else {
        println!("deny");
    }
    Ok(())
}
