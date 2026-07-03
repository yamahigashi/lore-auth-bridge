mod support;

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde_yaml_ng::{Mapping, Value};

#[test]
fn bridge_harness_writes_rust_config_file() -> Result<()> {
    if !support::require_e2e() {
        return Ok(());
    }

    let mut h = support::Harness::without_processes()?;
    h.set_authctl_bin(fake_authctl(h.dir())?);
    h.prepare_broker("127.0.0.1:18080", "127.0.0.1:18081", true)?;

    if h.bridge_config_path.as_os_str().is_empty() {
        bail!("bridge config path was not recorded");
    }
    let raw = fs::read_to_string(&h.bridge_config_path).context("read generated bridge config")?;
    let loaded: Value = serde_yaml_ng::from_str(&raw).context("parse generated bridge config")?;
    let root = loaded
        .as_mapping()
        .context("generated bridge config root is not a mapping")?;

    let server = yaml_mapping(root, "server")?;
    assert_eq!(yaml_string(server, "listen")?, "127.0.0.1:18080");
    assert_eq!(yaml_string(server, "grpc_listen")?, "127.0.0.1:18081");
    assert_eq!(
        yaml_string(server, "public_base_url")?,
        "http://localhost:18080"
    );

    let lore = yaml_mapping(root, "lore")?;
    assert_eq!(yaml_string(lore, "auth_url")?, "https://localhost:18081");

    let database = yaml_mapping(root, "database")?;
    assert_eq!(
        yaml_string(database, "path")?,
        h.db_path.display().to_string()
    );

    let jwt = yaml_mapping(root, "jwt")?;
    assert_eq!(yaml_string(jwt, "active_kid")?, "e2e-key-1");
    assert_eq!(
        yaml_string(jwt, "signing_key_dir")?,
        h.dir().join("keys").display().to_string()
    );

    let cert_file = yaml_string(server, "grpc_tls_cert_file")?;
    let key_file = yaml_string(server, "grpc_tls_key_file")?;
    if cert_file.is_empty() || key_file.is_empty() {
        bail!("gRPC TLS files were not written: {server:?}");
    }
    for path in [PathBuf::from(cert_file), PathBuf::from(key_file)] {
        if !path.exists() {
            bail!("expected generated file {}", path.display());
        }
    }
    if root.contains_key(Value::String("authz".to_owned())) {
        bail!("generated bridge config unexpectedly contains authz section");
    }
    Ok(())
}

#[test]
fn bridge_harness_external_command_uses_config_path() -> Result<()> {
    if !support::require_e2e() {
        return Ok(());
    }

    let mut h = support::Harness::without_processes()?;
    h.bridge_config_path = h.dir().join("bridge.yaml");
    let cmd = h.bridge_command(Path::new("/tmp/lore-auth-bridge"));

    assert_eq!(
        cmd.get_program(),
        Path::new("/tmp/lore-auth-bridge").as_os_str()
    );
    let args = cmd
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        args,
        vec![
            "--config".to_owned(),
            h.bridge_config_path.display().to_string()
        ]
    );
    assert_eq!(cmd.get_current_dir(), Some(h.dir()));
    Ok(())
}

#[test]
fn resolve_bridge_bin_makes_relative_path_independent_from_command_dir() -> Result<()> {
    if !support::require_e2e() {
        return Ok(());
    }

    let cwd = std::env::current_dir().context("working directory")?;
    let rel = Path::new("target").join("e2e-relative-lore-auth-bridge");
    let got = support::resolve_bridge_bin(&rel.display().to_string())?;
    let want = cwd.join(rel);

    assert_eq!(got, want);
    Ok(())
}

#[test]
fn bridge_harness_external_mode_starts_configured_bridge() -> Result<()> {
    if !support::require_e2e() {
        return Ok(());
    }

    let mut h = support::Harness::without_processes()?;
    h.start_broker()?;

    if !h.bridge_started() {
        bail!("external bridge process was not started");
    }
    Ok(())
}

fn yaml_mapping<'a>(parent: &'a Mapping, key: &str) -> Result<&'a Mapping> {
    let lookup = Value::String(key.to_owned());
    parent
        .get(&lookup)
        .with_context(|| format!("missing YAML key {key:?}"))?
        .as_mapping()
        .with_context(|| format!("YAML key {key:?} is not a mapping"))
}

fn yaml_string(parent: &Mapping, key: &str) -> Result<String> {
    let lookup = Value::String(key.to_owned());
    parent
        .get(&lookup)
        .with_context(|| format!("missing YAML key {key:?}"))?
        .as_str()
        .map(str::to_owned)
        .with_context(|| format!("YAML key {key:?} is not a string"))
}

fn fake_authctl(dir: &Path) -> Result<PathBuf> {
    let path = dir.join("fake-lore-authctl");
    fs::write(&path, "#!/bin/sh\nexit 0\n").context("write fake authctl")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .context("make fake authctl executable")?;
    }
    Ok(path)
}
