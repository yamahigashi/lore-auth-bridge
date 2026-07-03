# Deployment

[English](deployment.md)

このページでは、`lore-auth-bridge`、`loreserver`、任意の reverse proxy をどこに置くかを選びます。

[Configuration](configuration.ja.md) の前に読み、port、backup、log、recovery は [Operations](operations.ja.md) を参照します。

## 配置原則

deployment には次の process group があります。

- **bridge**：HTTP listener と gRPC listener を持つ `lore-auth-server` process。
- **loreserver**：client が clone と push で接続する Lore server process。
- **reverse proxy**：任意。通常は Caddy、NGINX、Apache、または bridge と場合によっては `loreserver` の前に置く CDN/WAF edge。

bridge と `loreserver` は同じ machine に置いても、別 machine に分けても構いません。

分けるかどうかは、bridge の制約ではなく、運用責任、network boundary、storage layout で決めます。

bridge の data は SQLite database と signing-key directory です。

どちらも block storage に支えられた local filesystem に置きます。

bridge の SQLite database を S3 などの object storage や NFS に置いてはいけません。

SQLite は filesystem locking と consistency semantics に依存しますが、object storage はそれを提供せず、network filesystem では壊れることがあります。

bridge の file permission と backup は [Operations](operations.ja.md#data-layout) を参照してください。

`loreserver` の repository data は Lore Server store settings で決まります。

Lore documentation では、`[immutable_store.local]` と `[mutable_store.local]` の path を使う direct local-store deployment が確認できます。

persistent local server では、両方の store path を durable local storage に設定します。

Lore Server config reference は、AWS 向けの `aws` mode など、plugin-backed store mode も列挙しています。

Lore の AWS storage example は、immutable fragment payload に S3、fragment metadata、association、mutable data、lock に DynamoDB を使います。

plugin が使えるかどうかは `loreserver` binary と distribution に依存するため、S3 や別の cloud store を選ぶ前に、使う Lore Server config reference と binary を確認してください。

## Reverse Proxy

本番では reverse proxy を推奨します。

public TLS termination、source restriction と rate limit、`/admin` の制限、複数 service の同居を一箇所で扱えるからです。

NGINX、Caddy、Apache はこの用途では同等の選択肢です。

certificate の自動管理を楽にしたい場合は Caddy が扱いやすいことがあります。

managed edge ACL、WAF rule、強い public rate limit が必要な場合は、Cloudflare などの CDN/WAF を reverse proxy の前に置けます。

最小構成では reverse proxy なしでも動かせます。

その場合、`/admin` は OIDC login、`admin.admin_emails`、任意の `security.admin_allowed_peer_cidrs` で守ります。

`RebacApi` は `security.rebac_allowed_peer_cidrs` で守り、Lore client 向けの gRPC TLS も設定します。

正確な listener と公開方針は [Operations](operations.ja.md#ports) を参照してください。

## Tailscale / VPN Mesh

この pattern は、bridge と Lore remote を public internet に出しません。

client は Tailscale などの private mesh network 経由で接続します。

小規模 team、固定 public IP や public DNS が不要な構成、TLS に Tailscale certificate を使いたい構成に向いています。

reverse proxy は省略しても、internal edge として残しても構いません。

network が private でも、bridge data と local store mode の `loreserver` store は persistent local block storage に置きます。

具体的な host、TLS、ReBAC allowlist の設定は [Tailscale](tailscale.ja.md) を参照してください。

## VPS / On-Prem

この pattern は、bridge、`loreserver`、Caddy などの reverse proxy を 1 台の machine に同居させます。

多くの team にとって最小の本番構成です。

bridge database と signing key、local store mode を使う場合の `loreserver` local store は、persistent local block storage に置きます。

小規模から中規模の team、data locality や data sovereignty を重視する構成、固定費の読みやすさを重視する構成に向いています。

server が開発者に近い場合や outbound transfer 条件がよい network を使う場合は、clone と pull の転送量が多い team にも向きます。

backup 手順は [Operations](operations.ja.md#backups) を参照してください。

## Cloud

この pattern は、bridge と `loreserver` を AWS、Azure、GCP、または同種の cloud platform で動かします。

bridge は login、token signing、ReBAC check が軽いため、小さい VM で足ります。

bridge の SQLite database と signing-key directory は、その VM の local block storage（EBS、Managed Disk、Persistent Disk など）に置きます。

bridge の SQLite database を object storage や NFS に置いてはいけません。

`loreserver` は、使用する Lore binary が対応する storage mode を使います。

確認できる local-store 構成では、`[immutable_store.local]` と `[mutable_store.local]` に persistent VM block storage を使います。

使う Lore distribution が AWS storage plugin に対応する場合、documented AWS shape は S3 だけではなく S3 と DynamoDB を使います。

Azure、GCP、その他の object store では、S3 向け設定を仮定せず、その Lore distribution の storage backend documentation に従ってください。

game asset workload では cloud egress が支配的な cost になり得ます。

cloud-hosted `loreserver` から開発者への clone と pull の転送量は、bridge traffic よりはるかに大きくなることがあります。

転送量の多い team は、オンプレ、outbound transfer が定額または有利な VPS、開発拠点に近い cloud region を検討してください。

この pattern は、すでに cloud 運用基盤がある組織、拠点が分散している team、managed backup tooling や cloud-native storage と monitoring を使いたい構成に向いています。

## 関連ページ

- [Configuration](configuration.ja.md)：bridge の具体的な設定。
- [Operations](operations.ja.md)：port、backup、log、recovery、token handling。
- [Loreserver](loreserver.ja.md)：bridge と `loreserver` の auth integration。
- [Tailscale](tailscale.ja.md)：private mesh variant。
