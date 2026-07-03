//! Database initialization command implementation.

use std::path::Path;

use anyhow::Result;

use crate::open_env;

pub(crate) async fn run(config_path: &Path, db: Option<&Path>) -> Result<()> {
    let env = open_env(config_path, db).await?;
    println!("database initialized: {}", env.db_path.display());
    Ok(())
}
