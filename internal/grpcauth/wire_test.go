package grpcauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	pb "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/epicurc"
)

// TestExchangeOverTLSWire proves the broker gRPC works over a TLS HTTP/2 wire,
// which is what the lore CLI requires (it always dials https:// for ucs-auth).
func TestExchangeOverTLSWire(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv, mem, tokenSvc := newTestServer()
	u := addAlice(mem)
	resource := addGameAssets(mem)
	mem.Grant(u.ID, resource.ResourceID)
	authn, _, err := tokenSvc.MintAuthn(ctx, u.ID, 0)
	if err != nil {
		t.Fatal(err)
	}

	serverCert, caPool := genCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcSrv := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&serverCert)))
	pb.RegisterUrcAuthApiServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(ln) }()
	defer grpcSrv.Stop()

	clientCreds := credentials.NewTLS(&tls.Config{RootCAs: caPool, ServerName: "127.0.0.1"})
	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(clientCreds))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := pb.NewUrcAuthApiClient(conn)

	if _, err := client.HealthCheck(ctx, &pb.HealthCheckRequest{}); err != nil {
		t.Fatalf("healthcheck: %v", err)
	}

	authCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+authn.Token))
	resp, err := client.ExchangeUserTokenForMultiresourceToken(authCtx, &pb.ExchangeUserTokenForMultiresourceTokenRequest{ResourceId: []string{resource.ResourceID}})
	if err != nil {
		t.Fatalf("exchange over TLS failed: %v", err)
	}
	if resp.GetToken().GetUserToken() == "" {
		t.Fatal("empty authz token")
	}
}

func genCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return cert, pool
}

func mustPKCS8(t *testing.T, priv *rsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
