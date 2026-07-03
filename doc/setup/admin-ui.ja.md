# 管理 Web UI

[English](admin-ui.md)

管理 Web UI は、login、JWKS、device flow、health check と同じ HTTP process で提供されます。

`admin.admin_emails` に 1 件以上の address がある場合だけ、`/admin` に mount されます。

`admin.admin_emails` を省略した場合、または空の場合、`/admin` は mount されず 404 を返します。

## UI の有効化

`lore-auth.yaml` に admin section を追加します。

```yaml
admin:
  admin_emails:
    - "admin@example.com"
```

列挙した address は正規化してから比較されます。

operator は、先に設定済みの OIDC login flow で sign in し、その後 `/admin` を開きます。

未認証 request と非 admin request は 404 を返します。

これにより、admin UI が有効かどうかを外部 probe に見せません。

## ネットワーク制限

`/admin` は公開 HTTP listener と同居します。

本番では、bridge を NGINX や Caddy などの reverse proxy の背後に置き、edge 側で `/admin` を制限してください。

公開境界で送信元制限や強い rate limit が必要な場合は、Cloudflare などの CDN または WAF も使います。

bridge は第二層の peer filter も持ちます。

```yaml
security:
  admin_allowed_peer_cidrs:
    - "127.0.0.1/32"
```

この判定は、bridge が直接見る TCP peer address を使います。

reverse proxy の背後では、proxy の address を許可し、公開側の admin allowlist は proxy で強制してください。

この判定では `X-Forwarded-For` を信頼しません。

reverse proxy なしの最小構成では、admin の防御は OIDC login、`admin.admin_emails`、任意の `security.admin_allowed_peer_cidrs` だけです。

## 機能

UI では repository、user、group、grant、user access を閲覧および検索できます。

user の追加と無効化、invitation 作成、manual repository の追加と無効化、grant 管理、group 管理ができます。

Users 画面では、招待がオンボーディングの主動線です。

user の直接追加は、ログイン binding を持たない account を作る advanced 操作です。

nested group 操作は常に使えます。

`/admin/simulator` の check simulator は、user、repository、action を入力して、設定済み authorization policy を実行します。

simulator は nested group path を含む grant 根拠も補助情報として表示します。

policy の結果が正です。

admin mutation は `admin_audit` に記録されます。

SQLite を直接確認する例です。

```bash
sqlite3 /var/lib/lore-auth/auth.sqlite3 \
  "SELECT created_at, actor, action, object_type, object_id, detail FROM admin_audit ORDER BY created_at DESC LIMIT 20;"
```

## 復旧

admin の再有効化と IdP 障害時の手順は [Operations](operations.ja.md#recovery) を参照してください。
