# TLS

[English](tls.md)

Lore の auth exchange は gRPC over TLS で到達できる必要があります。

bridge の HTTP/JWKS endpoint と、`UrcAuthApi` / `RebacApi` の gRPC endpoint は別です。

Hands-on Quickstart の構成では HTTP を `http://localhost:8080`、gRPC TLS を `https://localhost:8081` として扱います。

## mkcert

`mkcert` が使える環境では、ローカル CA を使うのが簡単です。

```bash
mkdir -p .quickstart/grpc

mkcert -cert-file .quickstart/grpc/tls.crt -key-file .quickstart/grpc/tls.key localhost 127.0.0.1

export TRUST_CERT_FILE="$(mkcert -CAROOT)/rootCA.pem"
export SSL_CERT_FILE="$TRUST_CERT_FILE"
```

`TRUST_CERT_FILE` は、`lore` と `loreserver` に渡す信頼 anchor です。

`mkcert` の場合は leaf certificate ではなく root CA を指定します。

## 自己署名証明書

`mkcert` がない場合は、短命の自己署名証明書でも確認できます。

```bash
mkdir -p .quickstart/grpc

openssl req -x509 -newkey rsa:2048 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout .quickstart/grpc/tls.key \
  -out .quickstart/grpc/tls.crt \
  -days 1

export TRUST_CERT_FILE="$PWD/.quickstart/grpc/tls.crt"
export SSL_CERT_FILE="$TRUST_CERT_FILE"
```

証明書には `localhost` または `127.0.0.1` を Subject Alternative Name として含めます。

CLI と config で `localhost` と `127.0.0.1` を混ぜると、証明書検証や JWT audience の切り分けが難しくなります。

どちらか一方に揃えてください。

## 本番証明書

本番では、bridge の gRPC endpoint に公開 hostname の証明書を設定します。

```yaml
server:
  grpc_listen: "0.0.0.0:8081"
  grpc_tls_cert_file: "/etc/lore-auth/grpc/tls.crt"
  grpc_tls_key_file: "/etc/lore-auth/grpc/tls.key"
```

証明書を reverse proxy や load balancer で終端する場合も、Lore が見る `auth_url` は TLS endpoint として到達できる必要があります。

## loreserver と lore CLI の信頼設定

この構成では、`loreserver` と `lore` CLI の両方に同じ `SSL_CERT_FILE` を渡します。

```bash
export SSL_CERT_FILE="$TRUST_CERT_FILE"
export LORE_CONFIG_PATH="$PWD/.quickstart/loreconfig"
export LORE_ENV=e2e
export HOME="$PWD/.quickstart/home"
```

`SSL_CERT_FILE` を設定していない場合、`lore auth login` が成功しても repository 操作時の authz exchange で失敗することがあります。

## よくある失敗: `SSL_CERT_FILE` が leaf 証明書を指している

次の症状が出たら、まずここを疑ってください。

- `lore auth login` は `Authentication successful` になる。
- しかし `lore repository create` が `code: 'Internal error', message: "Failed to connect to rebac service"` で失敗する。

原因は、`SSL_CERT_FILE` が mkcert の **leaf 証明書（`.quickstart/grpc/tls.crt`）** を指していることです。

`loreserver` は repository create のときに `auth_url`（gRPC TLS）へ ReBAC 同期で接続します。

その TLS 検証は `rustls` の native-roots で行われ、`rustls` は `SSL_CERT_FILE` が設定されているとそのファイルだけを信頼 anchor として使い、OS 証明書ストアを無視します。

mkcert の leaf は root CA（`rootCA.pem`）が発行したもので、それ自身は CA ではありません。

そのため leaf だけを信頼 anchor にすると、bridge が提示する証明書の検証経路を作れず、TLS handshake が失敗し、`connect()` が失敗して "Failed to connect to rebac service" になります。

`lore auth login --token` はトークンをローカルに保存するオフライン処理で、bridge への TLS 接続を伴いません。

このため login だけは成功してしまい、原因に気づきにくくなります。

### 直し方

mkcert を使う場合は、`SSL_CERT_FILE` に leaf ではなく **root CA** を指定します。

```bash
export SSL_CERT_FILE="$(mkcert -CAROOT)/rootCA.pem"
```

自己署名証明書（leaf 自身が自己の発行者）の場合のみ、leaf を指定してかまいません。

環境変数は起動時にしか読まれないため、変更後は `loreserver`（および同じ変数を使う `lore` CLI）を再起動します。

### 確認方法

`SSL_CERT_FILE` が信頼 anchor として正しいかは `openssl` で確認できます。

```bash
openssl verify -CAfile "$SSL_CERT_FILE" .quickstart/grpc/tls.crt
```

`OK` が返れば信頼 anchor として使えます。

`unable to get local issuer certificate` が返る場合は、`SSL_CERT_FILE` が leaf を指しています。

native-roots 方式をやめて OS ストアに統一したい場合は、`SSL_CERT_FILE` を設定せず `mkcert -install` で root CA を OS ストアに入れる方法もあります。
