package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/casbin"
	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/google"
	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/rs256"
	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/sqlite"
	"github.com/yamahigashi/lore-auth-bridge/internal/config"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/service"
	"github.com/yamahigashi/lore-auth-bridge/internal/device"
	"github.com/yamahigashi/lore-auth-bridge/internal/grpcauth"
	"github.com/yamahigashi/lore-auth-bridge/internal/grpcrebac"
	"github.com/yamahigashi/lore-auth-bridge/internal/httpserver"
	pbAuth "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/epicurc"
	pbRebac "github.com/yamahigashi/lore-auth-bridge/internal/loreproto/ucsauth"
)

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	configPath := flag.String("config", "configs/lore-auth.example.yaml", "config file")
	migrate := flag.Bool("migrate", true, "apply embedded migrations before serving")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	st, err := openConfiguredStore(context.Background(), cfg, *migrate)
	if err != nil {
		return err
	}
	defer st.Close()

	var googleAuthenticator *googleid.GoogleAuthenticator
	if cfg.Google.Enabled() {
		googleSecret, err := config.ReadSecretFile(cfg.Google.ClientSecretFile)
		if err != nil {
			return fmt.Errorf("startup: read google.client_secret_file: %w", err)
		}
		if googleSecret == "" {
			return fmt.Errorf("startup: google.client_secret_file %q is empty", cfg.Google.ClientSecretFile)
		}
		googleAuthenticator = googleid.New(googleConfigFromConfig(cfg, googleSecret))
	}

	coreStore := sqlite.NewCoreStore(st)
	authz := casbin.NewService(st)
	signer := rs256.NewSigner(cfg.JWT.ActiveKID, coreStore)
	if err := signer.Validate(context.Background()); err != nil {
		return fmt.Errorf("startup: signing key preflight failed: %w", err)
	}
	authServiceAudience, err := config.PublicHost(cfg.Server.PublicBaseURL)
	if err != nil {
		return fmt.Errorf("startup: public base url host: %w", err)
	}
	tokenSvc := service.NewTokenService(service.TokenConfig{
		Issuer:              cfg.JWT.Issuer,
		Audience:            cfg.JWT.Audience,
		AuthServiceAudience: authServiceAudience,
		AuthnTTL:            time.Duration(cfg.JWT.TTLSeconds) * time.Second,
		AuthzTTL:            15 * time.Minute,
	}, coreStore, coreStore, authz, signer, coreStore)
	loginSvc := service.NewLoginService(service.LoginConfig{
		PublicBaseURL:  cfg.Server.PublicBaseURL,
		SessionTTL:     time.Duration(cfg.Security.SessionTTLSeconds) * time.Second,
		AuthSessionTTL: time.Duration(cfg.Security.AuthSessionTTLSeconds) * time.Second,
	}, googleAuthenticator, coreStore, coreStore, tokenSvc)
	permissionSvc := service.NewPermissionService(coreStore, authz)
	resourceSvc := service.NewResourceService(coreStore)

	deviceSvc := device.NewService(cfg, st, tokenSvc)
	h := httpserver.NewWithOptions(httpserver.Options{Config: cfg, Login: loginSvc, Tokens: tokenSvc, Resources: resourceSvc, Permissions: permissionSvc, State: coreStore, JWKS: signer, Device: deviceSvc})
	httpSrv := newHTTPServer(cfg.Server.Listen, h.Handler())
	grpcOpts := []grpc.ServerOption{}
	rebacPeerPrefixes, err := grpcrebac.ParseAllowedPeerCIDRs(rebacAllowedPeerCIDRs(cfg))
	if err != nil {
		return fmt.Errorf("startup: parse security.rebac_allowed_peer_cidrs: %w", err)
	}
	grpcOpts = append(grpcOpts, grpc.ChainUnaryInterceptor(grpcrebac.UnaryPeerAllowlistInterceptor(rebacPeerPrefixes)))
	if cfg.Server.GRPCTLSCertFile != "" || cfg.Server.GRPCTLSKeyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(cfg.Server.GRPCTLSCertFile, cfg.Server.GRPCTLSKeyFile)
		if err != nil {
			return err
		}
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
	}
	grpcSrv := grpc.NewServer(grpcOpts...)
	pbAuth.RegisterUrcAuthApiServer(grpcSrv, grpcauth.New(grpcauth.Services{Login: loginSvc, Tokens: tokenSvc, Permissions: permissionSvc}))
	pbRebac.RegisterRebacApiServer(grpcSrv, grpcrebac.New(resourceSvc))

	errc := make(chan error, 2)
	go func() {
		log.Printf("HTTP listening on %s", cfg.Server.Listen)
		err := httpSrv.ListenAndServe()
		if err == http.ErrServerClosed {
			err = nil
		}
		errc <- err
	}()
	grpcLn, err := net.Listen("tcp", cfg.Server.GRPCListen)
	if err != nil {
		return err
	}
	go func() {
		log.Printf("gRPC listening on %s", cfg.Server.GRPCListen)
		errc <- grpcSrv.Serve(grpcLn)
	}()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		return err
	case <-sigc:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
		grpcSrv.GracefulStop()
		return nil
	}
}

func rebacAllowedPeerCIDRs(cfg *config.Config) []string {
	if cfg == nil || len(cfg.Security.RebacAllowedPeerCIDRs) == 0 {
		return grpcrebac.DefaultAllowedPeerCIDRs()
	}
	return cfg.Security.RebacAllowedPeerCIDRs
}

func googleConfigFromConfig(cfg *config.Config, clientSecret string) googleid.Config {
	return googleid.Config{
		ClientID:              cfg.Google.ClientID,
		ClientSecret:          clientSecret,
		RedirectURL:           cfg.Google.RedirectURL,
		AllowedHostedDomains:  cfg.Google.AllowedHostedDomains,
		AllowPersonalAccounts: cfg.Google.AllowPersonalAccounts,
	}
}

func openConfiguredStore(ctx context.Context, cfg *config.Config, migrate bool) (*sqlite.Store, error) {
	st, err := sqlite.Open(cfg.Database.Path)
	if err != nil {
		return nil, fmt.Errorf("startup: open database %q: %w", cfg.Database.Path, err)
	}
	if migrate {
		if err := st.Migrate(ctx); err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("startup: migrate database %q: %w", cfg.Database.Path, err)
		}
		return st, nil
	}
	if err := st.ValidateSchema(ctx); err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("startup: validate database schema %q: %w", cfg.Database.Path, err)
	}
	return st, nil
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}
