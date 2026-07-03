# End-to-end test

このディレクトリは、実際の `lore` / `loreserver` バイナリに対して
lore-auth-bridge を通しで検証する E2E テストです。

通常のユニットテスト (`go test ./...`) からは build tag `e2e` で分離されており、
`LORE_E2E=1` のときだけ実行されます。

## 前提

- `lore` と `loreserver` が PATH 上にインストール済みであること。
- Rust 版 `lore-auth-server` と `lore-authctl` をビルド済みであること。

```bash
curl -fsSL https://raw.githubusercontent.com/EpicGames/lore/main/scripts/install.sh | bash
cargo build -p lore-auth-server -p lore-authctl
```

## 実行

```bash
test/e2e/run.sh
```

または直接:

```bash
LORE_E2E=1 \
LORE_E2E_BRIDGE_BIN=target/debug/lore-auth-server \
LORE_E2E_AUTHCTL_BIN=target/debug/lore-authctl \
go test -tags e2e -count=1 -v ./test/e2e/...
```

`LORE_E2E` 未設定、`LORE_E2E_BRIDGE_BIN` 未設定、`LORE_E2E_AUTHCTL_BIN` 未設定、
または `lore`/`loreserver` が見つからない場合はスキップされます。

E2E harness は Go の in-process bridge を起動しません。
`LORE_E2E_BRIDGE_BIN` に指定した外部 bridge を `--config <generated-yaml>` で起動し、
`LORE_E2E_AUTHCTL_BIN` に指定した authctl で DB 初期化、user 作成、repo 作成、grant 付与、signing key 生成、authn token 発行を行います。

```bash
cargo build -p lore-auth-server -p lore-authctl
LORE_E2E=1 \
LORE_E2E_BRIDGE_BIN=target/debug/lore-auth-server \
LORE_E2E_AUTHCTL_BIN=target/debug/lore-authctl \
go test -tags e2e -count=1 -v ./test/e2e/...
```

## 構成

- broker (HTTP/JWKS + gRPC/TLS) は `LORE_E2E_BRIDGE_BIN` の外部プロセスとして、127.0.0.1 のランダムポートに起動します。
- harness は Rust config 形式の YAML を temp dir に生成します。
  - `lore.auth_url` は `ucs-auth://localhost:<grpc-port>` です。
  - SQLite DB と signing key directory も temp dir に作ります。
- `loreserver` は別プロセスで起動し、auth を有効化して broker の JWKS を信頼します。
  - 設定は `LORE_CONFIG_PATH` の env layer (`e2e.toml`) として注入します。
  - すべて `127.0.0.1` で完結し、`lore://`（末尾 s なし）なので QUIC は自己署名証明書でも検証スキップされます。
- `lore` CLI を `HOME=<tempdir>` で実行し、token store を汚しません。
- テスト中の DB 状態確認（repository sync / soft delete など）は `modernc.org/sqlite` で direct SQL を読みます。

## 検証している内容（acceptance matrix）

| Test | 内容 | 期待 |
| ---- | ---- | ---- |
| `TestTrustChain` | JWKS 信頼チェーン + authn login | 成功 |
| `TestRepositoryWorkflow` | login → repository create → ReBAC sync → grant → clone | 成功 |
| `TestExactResourceClone` | grant 済み exact `urc-{repo}` で clone | 成功 |
| `TestNoGrantDeniedAtExchange` | grant なしで `ExchangeUserTokenForMultiresourceToken` | `PermissionDenied` |
| `TestWrongResourceDenied` | 別 repo の grant のみで対象 repo exchange | `PermissionDenied` |
| `TestDisabledUserDenied` | token 発行後に user disabled → exchange | `Unauthenticated` |
| `TestExpiredAuthnRejected` | expired authn token で exchange | `Unauthenticated` |
| `TestWrongAudienceRejected` | auth service audience を含まない authn token で exchange | `Unauthenticated` |
| `TestLookupUserPermissions` | grant 後の `LookupUserPermissions` | 対象 resource を返す |
| `TestRebacCreateThenDelete` | ReBAC `CreateResource` / `DeleteResource` | DB が active → deleted |
| `TestReadOnlyPushBehavior` | `permission:["read"]` で push | 現時点では明示 skip（仕様保証に使わない） |

broker は自己署名 CA を使った gRPC/TLS で起動し、CA を `SSL_CERT_FILE` で lore/loreserver と Go gRPC client に信頼させ、`localhost` で UCS Auth + ReBAC の通し動作を検証します。

## 調整ポイント

- `loreserver` が base `default.toml` を必要とする場合は、環境変数
  `LORE_E2E_DEFAULT_TOML=/path/to/default.toml` を指定すると config dir にコピーします。
- bridge 設定は `authz.backend` を省略し、default の ReBAC backend で起動します。
- `lore` CLI の出力フォーマットが異なる場合は `e2e_test.go` の `repoIDRe`
  と `cloneOrPush` を実環境に合わせて調整してください。
