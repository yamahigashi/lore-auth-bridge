//! Token minting command implementations.

use std::path::Path;

use crate::{TokenCommand, build_token_service, core_error, emit_token, open_env};
use anyhow::{Context, Result};

pub(crate) async fn run(
    config_path: &Path,
    db: Option<&Path>,
    command: TokenCommand,
) -> Result<()> {
    let env = open_env(config_path, db).await?;
    let tokens = build_token_service(&env).await?;
    match command {
        TokenCommand::Mint(args) => {
            let user = env
                .store
                .resolve_user(&args.user)
                .await
                .map_err(core_error)
                .with_context(|| format!("resolve user {:?}", args.user))?;
            let signed = tokens
                .manual_mint_authz(&user.id, &args.repo, &args.role, args.ttl)
                .await
                .map_err(core_error)?;
            emit_token(
                "token",
                &signed.token,
                args.out.as_deref(),
                args.print_login_command,
                &env.cfg,
            )?;
        }
        TokenCommand::MintAuthn(args) => {
            let user = env
                .store
                .resolve_user(&args.user)
                .await
                .map_err(core_error)
                .with_context(|| format!("resolve user {:?}", args.user))?;
            let (signed, _) = tokens
                .mint_authn(&user.id, args.ttl)
                .await
                .map_err(core_error)?;
            emit_token(
                "authn token",
                &signed.token,
                args.out.as_deref(),
                args.print_login_command,
                &env.cfg,
            )?;
        }
    }
    Ok(())
}
