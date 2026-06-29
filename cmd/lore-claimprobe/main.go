package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/rs256"
)

const (
	defaultKid        = "lore-probe-2026-06-29-01"
	defaultIssuer     = "https://auth.example.com"
	defaultAudience   = "lore-service,lore.example.com"
	defaultSubject    = "google:TEST_SUBJECT"
	defaultName       = "Test User"
	defaultUsername   = "test@example.com"
	defaultAuthURL    = "ucs-auth://auth.example.com"
	defaultRemoteURL  = "lore://lore.example.com:41337"
	defaultPrivateKey = "probe-private.pem"
	defaultJWKS       = "jwks.json"
)

func main() {
	log.SetFlags(0)
	if err := run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	if len(args) < 2 {
		usage(os.Stderr)
		return errors.New("missing command")
	}
	switch args[1] {
	case "keygen":
		return cmdKeygen(args[2:])
	case "jwks":
		return cmdJWKS(args[2:])
	case "serve":
		return cmdServe(args[2:])
	case "mint":
		return cmdMint(args[2:])
	case "decode":
		return cmdDecode(args[2:])
	case "version":
		return cmdVersion(args[2:])
	case "help", "-h", "--help":
		usage(os.Stdout)
		return nil
	default:
		usage(os.Stderr)
		return fmt.Errorf("unknown command %q", args[1])
	}
}

func usage(out *os.File) {
	fmt.Fprint(out, `lore-claimprobe probes the provisional Lore JWT claim contract.

Commands:
  keygen   Generate an RS256 private key and JWKS file.
  jwks     Export JWKS from an existing private key.
  serve    Serve a JWKS file over HTTP.
  mint     Mint a probe Lore JWT.
  decode   Insecurely decode a compact JWT for inspection.
  version  Print local lore/loreserver versions when available.

Typical flow:
  lore-claimprobe keygen --kid lore-probe-1 --out-dir .probe
  lore-claimprobe serve --jwks .probe/jwks.json --listen 127.0.0.1:8000
  lore-claimprobe mint --key .probe/probe-private.pem --kid lore-probe-1 \
    --issuer https://auth.example.com \
    --audience lore-service,lore.example.com \
    --repository-id 0194b726b34e72b0b45550b88a967076 \
    --remote-url lore://lore.example.com:41337
`)
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	kid := fs.String("kid", defaultKid, "JWK/JWT key id")
	outDir := fs.String("out-dir", ".probe", "output directory")
	bits := fs.Int("bits", rs256.DefaultRSABits, "RSA modulus bits")
	privateName := fs.String("private-name", defaultPrivateKey, "private key filename within out-dir")
	jwksName := fs.String("jwks-name", defaultJWKS, "JWKS filename within out-dir")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := rs256.GenerateSigningKey(*kid, *bits)
	if err != nil {
		return err
	}
	privatePath := filepath.Join(*outDir, *privateName)
	jwksPath := filepath.Join(*outDir, *jwksName)
	if err := key.WritePrivatePEM(privatePath); err != nil {
		return err
	}
	jwks, err := rs256.MarshalJWKS(key.JWKS())
	if err != nil {
		return err
	}
	if err := os.WriteFile(jwksPath, append(jwks, '\n'), 0o644); err != nil {
		return fmt.Errorf("write JWKS: %w", err)
	}
	fmt.Printf("kid: %s\n", *kid)
	fmt.Printf("private_key: %s\n", privatePath)
	fmt.Printf("jwks: %s\n", jwksPath)
	fmt.Printf("jwks_endpoint_hint: http://127.0.0.1:8000/.well-known/jwks.json\n")
	return nil
}

func cmdJWKS(args []string) error {
	fs := flag.NewFlagSet("jwks", flag.ContinueOnError)
	keyPath := fs.String("key", defaultPrivateKey, "RSA private key PEM")
	kid := fs.String("kid", defaultKid, "JWK/JWT key id")
	out := fs.String("out", "", "output file (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := rs256.LoadSigningKeyPEM(*keyPath, *kid)
	if err != nil {
		return err
	}
	jwks, err := rs256.MarshalJWKS(key.JWKS())
	if err != nil {
		return err
	}
	jwks = append(jwks, '\n')
	if *out == "" {
		_, err = os.Stdout.Write(jwks)
		return err
	}
	return os.WriteFile(*out, jwks, 0o644)
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	jwksPath := fs.String("jwks", defaultJWKS, "JWKS JSON file to serve")
	listen := fs.String("listen", "127.0.0.1:8000", "listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		raw, err := os.ReadFile(*jwksPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, "lore-claimprobe JWKS server")
		_, _ = fmt.Fprintln(w, "/.well-known/jwks.json")
	})
	log.Printf("serving JWKS %s at http://%s/.well-known/jwks.json", *jwksPath, *listen)
	return http.ListenAndServe(*listen, mux)
}

func cmdMint(args []string) error {
	fs := flag.NewFlagSet("mint", flag.ContinueOnError)
	keyPath := fs.String("key", defaultPrivateKey, "RSA private key PEM")
	kid := fs.String("kid", defaultKid, "JWK/JWT key id")
	issuer := fs.String("issuer", defaultIssuer, "JWT iss")
	audience := fs.String("audience", defaultAudience, "comma-separated JWT aud values")
	subject := fs.String("subject", defaultSubject, "JWT sub")
	name := fs.String("name", defaultName, "JWT name")
	username := fs.String("preferred-username", defaultUsername, "JWT preferred_username")
	groups := fs.String("groups", "test", "comma-separated JWT groups")
	idp := fs.String("idp", "google", "JWT idp")
	env := fs.String("env", rs256.DefaultEnv, "JWT env")
	repositoryID := fs.String("repository-id", "", "Lore repository id; emits urc-{id}")
	resourceID := fs.String("resource-id", "", "explicit resource id (urc-..., urc-*, or wrong id)")
	noResources := fs.Bool("no-resources", false, "omit resources claim entirely for negative probe case B")
	permissions := fs.String("permissions", "read,write", "comma-separated resources[].permission")
	ttl := fs.Duration("ttl", time.Hour, "token TTL, e.g. 15m, 1h, -1h for expired")
	jti := fs.String("jti", "", "optional JWT jti")
	authURL := fs.String("auth-url", defaultAuthURL, "auth URL for printed lore auth login command")
	remoteURL := fs.String("remote-url", defaultRemoteURL, "Lore remote URL for printed lore auth login command")
	printCommand := fs.Bool("print-login-command", true, "print lore auth login command after token")
	out := fs.String("out", "", "write token to file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	resID := chooseResourceID(*resourceID, *repositoryID)
	if resID == "" && !*noResources {
		return errors.New("mint requires --repository-id or --resource-id")
	}
	key, err := rs256.LoadSigningKeyPEM(*keyPath, *kid)
	if err != nil {
		return err
	}
	claims, err := rs256.NewLoreClaims(rs256.ClaimsOptions{
		Issuer:            *issuer,
		Audience:          splitCSV(*audience),
		Subject:           *subject,
		Env:               *env,
		Name:              *name,
		PreferredUsername: *username,
		Groups:            splitCSV(*groups),
		IDP:               *idp,
		ResourceID:        resID,
		Permissions:       splitCSV(*permissions),
		WithoutResources:  *noResources,
		TTL:               *ttl,
		JTI:               *jti,
	})
	if err != nil {
		return err
	}
	jwt, err := key.SignLoreClaims(claims)
	if err != nil {
		return err
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(jwt+"\n"), 0o600); err != nil {
			return fmt.Errorf("write token: %w", err)
		}
		fmt.Printf("token: %s\n", *out)
	} else {
		fmt.Println(jwt)
	}
	if *printCommand {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "lore auth login command:")
		fmt.Fprintf(os.Stderr, "  lore auth login --token-type lore --token %s --auth-url %s %s\n", shellQuote(jwt), shellQuote(*authURL), shellQuote(*remoteURL))
	}
	return nil
}

func cmdDecode(args []string) error {
	fs := flag.NewFlagSet("decode", flag.ContinueOnError)
	tokenArg := fs.String("token", "", "compact JWT; if empty reads stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	compact := *tokenArg
	if compact == "" {
		raw, err := os.ReadFile("/dev/stdin")
		if err != nil {
			return err
		}
		compact = strings.TrimSpace(string(raw))
	}
	header, payload, err := rs256.DecodeInsecure(compact)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"header": header, "payload": payload})
}

func cmdVersion(args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	for _, name := range []string{"lore", "loreserver", "lore-server"} {
		path, err := exec.LookPath(name)
		if err != nil {
			fmt.Printf("%s: not found\n", name)
			continue
		}
		fmt.Printf("%s: %s\n", name, path)
		for _, argv := range [][]string{{"--version"}, {"version"}} {
			out, err := exec.Command(path, argv...).CombinedOutput()
			if err == nil {
				fmt.Printf("%s %s: %s", name, strings.Join(argv, " "), string(out))
				if len(out) == 0 || out[len(out)-1] != '\n' {
					fmt.Println()
				}
				break
			}
		}
	}
	return nil
}

func chooseResourceID(explicit, repositoryID string) string {
	if explicit != "" {
		return explicit
	}
	return rs256.ResourceIDForRepositoryID(repositoryID)
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' || r == '/' || r == ':' || r == '=' || r == ',' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) == -1 {
		return s
	}
	return strconv.Quote(s)
}
