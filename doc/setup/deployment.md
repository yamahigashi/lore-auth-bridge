# Deployment

[日本語](deployment.ja.md)

This page helps choose where to run `lore-auth-bridge`, `loreserver`, and an optional reverse proxy.

Use it before [Configuration](configuration.md), then keep [Operations](operations.md) nearby for ports, backups, logs, and recovery.

## Placement Principles

A deployment has three process groups:

- **bridge**: one `lore-auth-server` process with an HTTP listener and a gRPC listener.
- **loreserver**: the Lore server process that clients clone from and push to.
- **reverse proxy**: optional, usually Caddy, NGINX, Apache, or a CDN/WAF edge in front of the bridge and sometimes `loreserver`.

The bridge and `loreserver` may run on the same machine or on separate machines.

Choose separation for operational ownership, network boundaries, and storage layout, not because the bridge requires it.

Bridge data is the SQLite database plus the signing-key directory.

Keep both on a local filesystem backed by block storage.

Do not put the bridge SQLite database on object storage such as S3, or on NFS.

SQLite relies on filesystem locking and consistency semantics that object storage does not provide and network filesystems can break.

For bridge file permissions and backups, see [Operations](operations.md#data-layout).

`loreserver` repository data is controlled by Lore Server store settings.

The Lore documentation confirms a direct local-store deployment with `[immutable_store.local]` and `[mutable_store.local]` paths.

For a persistent local server, set both store paths to durable local storage.

The Lore Server config reference also lists plugin-backed store modes, including an AWS-oriented `aws` mode.

The Lore AWS storage example uses S3 for immutable fragment payloads and DynamoDB for fragment metadata, associations, mutable data, and locks.

Plugin availability depends on the `loreserver` binary and distribution, so verify the Lore Server config reference and the binary you deploy before choosing S3 or another cloud store.

## Reverse Proxy

A reverse proxy is recommended for production.

It gives one place to terminate public TLS, apply source restrictions and rate limits, restrict `/admin`, and host several services behind one public name.

NGINX, Caddy, and Apache are equivalent choices for this role.

Caddy is often simpler when automatic certificate management is useful.

Cloudflare or another CDN/WAF can also sit in front of the reverse proxy when the deployment needs managed edge ACLs, WAF rules, or stronger public rate limiting.

A minimal deployment can run without a reverse proxy.

In that case, `/admin` is protected by OIDC login, `admin.admin_emails`, and optionally `security.admin_allowed_peer_cidrs`.

`RebacApi` is protected by `security.rebac_allowed_peer_cidrs`, and gRPC TLS still needs to be configured for Lore clients.

For the exact listeners and exposure guidance, see [Operations](operations.md#ports).

## Tailscale / VPN Mesh

This pattern keeps the bridge and Lore remote off the public internet.

Clients reach them through Tailscale or another private mesh network.

It fits small teams, setups that do not need fixed public IP addresses or public DNS, and deployments that want to use Tailscale certificates for TLS.

The reverse proxy can be skipped or kept as an internal edge.

Keep bridge data and any local `loreserver` store on persistent local block storage even when the network is private.

See [Tailscale](tailscale.md) for the concrete host, TLS, and ReBAC allowlist settings.

## VPS / On-Prem

This pattern runs the bridge, `loreserver`, and Caddy or another reverse proxy on one machine.

It is the smallest production shape for many teams.

Use persistent local block storage for the bridge database and signing keys, and for `loreserver` local stores when local store mode is used.

It fits small to medium teams, deployments that value data locality or data sovereignty, and setups where predictable fixed infrastructure cost matters.

It also fits teams with high clone and pull traffic when the server is near the developers or on a network with favorable outbound transfer terms.

For backup procedures, see [Operations](operations.md#backups).

## Cloud

This pattern runs the bridge and `loreserver` on AWS, Azure, GCP, or a similar cloud platform.

The bridge is usually a small VM because login, token signing, and ReBAC checks are lightweight.

Place the bridge SQLite database and signing-key directory on that VM's local block storage, such as EBS, Managed Disk, or Persistent Disk.

Do not place the bridge SQLite database on object storage or NFS.

For `loreserver`, use the storage mode supported by the Lore binary you deploy.

The confirmed local-store shape uses persistent VM block storage for `[immutable_store.local]` and `[mutable_store.local]`.

When your Lore distribution supports the AWS storage plugin, the documented AWS shape uses S3 plus DynamoDB rather than only S3.

For Azure, GCP, or another object store, follow the storage backend documentation for that Lore distribution instead of assuming S3-style settings apply.

Cloud egress can dominate cost for game-asset workloads.

Clone and pull traffic from cloud-hosted `loreserver` to developers can be much larger than the bridge traffic.

Teams with heavy transfer volume should consider on-prem, VPS providers with flat or favorable outbound transfer terms, or cloud regions close to development sites.

This pattern fits organizations that already operate in cloud, have distributed sites, need managed backup tooling, or want cloud-native storage and monitoring.

## Related Pages

- [Configuration](configuration.md) for concrete bridge settings.
- [Operations](operations.md) for ports, backups, logs, recovery, and token handling.
- [Loreserver](loreserver.md) for bridge and `loreserver` auth integration.
- [Tailscale](tailscale.md) for the private-mesh variant.
