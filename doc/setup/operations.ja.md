# Operations

[English](operations.md)

このページは、port、local data、backup、log、recovery、browser token page、device flow の運用リファレンスです。

[Configuration](configuration.ja.md)、[Authctl](authctl.ja.md)、[管理 Web UI](admin-ui.ja.md) と合わせて使います。

## Ports

| Listener | 既定値 | 乗るもの | 公開要否 |
| --- | --- | --- | --- |
| HTTP `server.listen` | `127.0.0.1:8080` | `/.well-known/jwks.json`、`/healthz`、`/login`、`/auth/{provider}/*`、`/tokens`、`/device`、`/api/device/*`、任意の `/admin` | user または `loreserver` から到達させる場合は HTTPS reverse proxy の背後に置きます。`/admin` は edge で制限します。 |
| gRPC `server.grpc_listen` | `127.0.0.1:8081` | auth session と token exchange 用の `epic_urc.UrcAuthApi`、repository create/delete sync 用の `ucs.auth.RebacApi` | Lore CLI と `loreserver` から TLS で到達させます。`RebacApi` は `security.rebac_allowed_peer_cidrs` または edge ACL で `loreserver` に制限します。 |

HTTP と gRPC は別 socket です。

reverse proxy がどちらかの listener の前にある場合、bridge から見える immediate TCP peer は proxy です。

## Data Layout

`database.path` は main SQLite database file を指します。

server は database を開くときに parent directory を作成します。

database には user、group、repository、grant、auth session、device authorization、issued-token metadata、signing-key metadata、admin audit entry が入ります。

issued-token metadata には JWT 本文は入りません。

SQLite adapter は WAL mode を有効にするため、稼働中の server は main database の隣に `-wal` と `-shm` file を作ることがあります。

database directory は service user だけが読み書きできる権限にします。

`jwt.signing_key_dir` には signing key の private PEM file を置きます。

Unix では、`key generate` が directory を mode `0700`、private key file を mode `0600` で作成します。

database には public JWK と private key path が保存されるため、database と signing-key directory は同じ backup set から復元します。

## Backups

offline backup では、`lore-auth-server` と DB に書き込み得る `lore-authctl` process を止めてから、database と signing-key directory を copy します。

停止後も database の隣に `-wal` または `-shm` file が残っている場合は、main database file と一緒に copy するか、SQLite backup を作ります。

```bash
sudo systemctl stop lore-auth-server
cp -a /var/lib/lore-auth/lore-auth.sqlite3* /backup/lore-auth/
cp -a /etc/lore-auth/keys /backup/lore-auth/keys
```

live backup では、main database file の copy ではなく SQLite の backup mechanism を使います。

次のどちらも単一の SQLite backup file を作ります。

```bash
sqlite3 /var/lib/lore-auth/lore-auth.sqlite3 ".backup '/backup/lore-auth.sqlite3'"
sqlite3 /var/lib/lore-auth/lore-auth.sqlite3 "VACUUM INTO '/backup/lore-auth-vacuum.sqlite3';"
```

signing-key directory は database と同じタイミングで backup します。

private key file がないと、既存の signed token と設定済み active key を restore 後に使えません。

## Logs

`lore-auth-server` は `tracing_subscriber` と `RUST_LOG` を使います。

`RUST_LOG` を設定しない場合の default filter は `info,authz_core=warn` です。

```bash
RUST_LOG=info,lore_auth_server=debug,lore_auth_inbound=debug \
  lore-auth-server --config /etc/lore-auth/lore-auth.yaml
```

issued-token log は `jti`、kind、user、resource、key ID、audience、issue time、expiry などの metadata を保存します。

JWT 本文は保存しません。

server は token 本文を意図的には log に出しません。

一方で、`--out` なしの `lore-authctl token mint-authn`、`--print-login-command`、`token mint`、下記の Web Token Page など、運用者向け flow は設計上 token 本文を表示します。

これらの出力を共有 terminal、CI log、shell history、browser history、共有 clipboard manager、support log に残さないでください。

reverse-proxy access log は、OAuth `code`、device `user_code`、`/login/session/{nonce}`、token 本文などの query string と sensitive path value を省略または redact する設定にします。

## Recovery

admin user を誤って disable した場合は、`authctl` で account を有効化します。

```bash
lore-authctl --config /etc/lore-auth/lore-auth.yaml user enable admin@example.com
```

IdP が利用できない場合は、`lore-authctl` で管理変更を続けます。

CLI は Web UI と同じ audited administrative adapter 経由で書き込みます。

IdP を使わずに Lore に入る場合は、[Authctl](authctl.ja.md#token-mint-authn) の手順で user を登録し、authn token を発行します。

## Web Token Page

HTTP server は browser から Lore token を発行する `/tokens` と `/tokens/mint` を提供します。

`/tokens` はログイン済み browser session を要求し、未ログインなら `/login` に redirect します。

現在の user に write permission がある repository だけを一覧します。

`/tokens/mint` は same-origin header と CSRF token を確認し、選択された repository の writer authz token を発行します。

結果画面には token 本文と `lore auth login --token-type lore` command が表示されます。

この page は信頼できる private browser session だけで使い、結果を screenshot、browser history、共有 clipboard manager、support log に残さないでください。

## Device Flow

Device flow は、interactive browser を持たない Lore CLI または helper が、ログイン済み user に browser で承認してもらい repository token を取得するための HTTP 経路です。

`/api/device/start` は `remote_url` と `repository` を含む JSON を受け取り、`device_code`、`user_code`、`verification_uri`、`expires_in`、`interval` を返します。

`/device` は browser verification page です。

code の承認にはログイン済み browser session が必要で、承認 user が対象 repository への write access を持つ場合だけ成功します。

`/api/device/token` は polling endpoint です。

承認後は `token_type: "lore"`、authz `access_token`、設定済み `auth_url`、repository の `remote_url` を返します。

caller はこれらの値を使い、CLI 環境に browser を埋め込まずに `lore auth login --token-type lore` 相当の login を完了します。

関連する設定は [Configuration](configuration.ja.md#security) の `security.device_code_ttl_seconds` と `security.device_poll_interval_seconds` です。
