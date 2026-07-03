//! Group membership and nesting command implementations.

use std::path::Path;

use anyhow::Result;
use lore_auth_core::ports::{GroupAdmin, GroupQuery};

use crate::{
    GroupCommand, GroupMemberCommand, GroupNestCommand, authctl_actor, core_error, open_env,
};

pub(crate) async fn run(
    config_path: &Path,
    db: Option<&Path>,
    command: GroupCommand,
) -> Result<()> {
    let env = open_env(config_path, db).await?;
    let groups = env.store.audited(authctl_actor());
    match command {
        GroupCommand::Add(args) => {
            let group = groups
                .add_group(&args.name, &args.description)
                .await
                .map_err(core_error)?;
            println!("{}\t{}", group.id, group.name);
        }
        GroupCommand::List => {
            for group in env.store.list_groups().await.map_err(core_error)? {
                println!("{}\t{}", group.id, group.name);
            }
        }
        GroupCommand::Member { command } => match command {
            GroupMemberCommand::Add(args) => {
                groups
                    .add_group_member(&args.group, &args.user)
                    .await
                    .map_err(core_error)?;
                println!("ok");
            }
            GroupMemberCommand::Remove(args) => {
                groups
                    .remove_group_member(&args.group, &args.user)
                    .await
                    .map_err(core_error)?;
                println!("ok");
            }
        },
        GroupCommand::Nest { command } => match command {
            GroupNestCommand::Add(args) => {
                groups
                    .add_group_group(&args.parent_group, &args.member_group)
                    .await
                    .map_err(core_error)?;
                println!("ok");
            }
            GroupNestCommand::Remove(args) => {
                groups
                    .remove_group_group(&args.parent_group, &args.member_group)
                    .await
                    .map_err(core_error)?;
                println!("ok");
            }
        },
    }
    Ok(())
}
