package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/casbin"
	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/rs256"
	"github.com/yamahigashi/lore-auth-bridge/internal/adapter/sqlite"
	"github.com/yamahigashi/lore-auth-bridge/internal/config"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/model"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/ports"
	"github.com/yamahigashi/lore-auth-bridge/internal/core/service"
)

func main() {
	log.SetFlags(0)
	if err := run(os.Args); err != nil {
		log.Fatal(err)
	}
}

type cliEnv struct {
	cfg         *config.Config
	store       *sqlite.Store
	core        *sqlite.CoreStore
	authz       *casbin.Service
	groups      ports.GroupAdmin
	grants      ports.GrantAdmin
	keys        ports.SigningKeyAdmin
	tokens      *service.TokenService
	permissions *service.PermissionService
}

func run(args []string) error {
	if len(args) < 2 {
		usage()
		return fmt.Errorf("missing command")
	}
	switch args[1] {
	case "init-db":
		return cmdInitDB(args[2:])
	case "key":
		return cmdKey(args[2:])
	case "user":
		return cmdUser(args[2:])
	case "group":
		return cmdGroup(args[2:])
	case "repo":
		return cmdRepo(args[2:])
	case "grant":
		return cmdGrant(args[2:])
	case "check":
		return cmdCheck(args[2:])
	case "token":
		return cmdToken(args[2:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[1])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `lore-authctl manages lore-auth-bridge.

Commands:
  init-db
  key generate|list
  user add|invite|list|disable
  group add|list|member add|member remove
  repo add|list
  grant add|list|remove
  check <user-email-or-id> <repo> <read|write|admin>
  token mint <user-email-or-id> <repo>
  token mint-authn <user-email-or-id>
`)
}

func commonFlags(name string, args []string) (*flag.FlagSet, *string, *string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	configPath := fs.String("config", "configs/lore-auth.example.yaml", "config file")
	dbPath := fs.String("db", "", "override database path")
	return fs, configPath, dbPath, fs.Parse(args)
}

func openEnv(configPath, dbPath string) (*cliEnv, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config %q: %w", configPath, err)
	}
	path := cfg.Database.Path
	if dbPath != "" {
		path = dbPath
	}
	st, err := openStore(path)
	if err != nil {
		return nil, fmt.Errorf("open database %q: %w", path, err)
	}
	coreStore := sqlite.NewCoreStore(st)
	authz := casbin.NewService(st)
	tokens := service.NewTokenService(tokenConfigFromConfig(cfg), coreStore, coreStore, authz, rs256.NewSigner(cfg.JWT.ActiveKID, coreStore), coreStore)
	keyAdmin := rs256.NewSigningKeyAdmin(cfg.JWT.SigningKeyDir, coreStore)
	return &cliEnv{cfg: cfg, store: st, core: coreStore, authz: authz, groups: coreStore, grants: coreStore, keys: keyAdmin, tokens: tokens, permissions: service.NewPermissionService(coreStore, authz)}, nil
}

func (e *cliEnv) close() { _ = e.store.Close() }

func cmdInitDB(args []string) error {
	fs, configPath, dbPath, err := commonFlags("init-db", args)
	_ = fs
	if err != nil {
		return err
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	path := env.cfg.Database.Path
	if *dbPath != "" {
		path = *dbPath
	}
	fmt.Printf("database initialized: %s\n", path)
	return nil
}

func cmdKey(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("key requires subcommand: generate or list")
	}
	switch args[0] {
	case "generate":
		return cmdKeyGenerate(args[1:])
	case "list":
		return cmdKeyList(args[1:])
	default:
		return fmt.Errorf("unknown key subcommand %q", args[0])
	}
}

func cmdKeyGenerate(args []string) error {
	fs, configPath, dbPath, err := commonFlags("key generate", nil)
	if err != nil {
		return err
	}
	kid := fs.String("kid", "", "key id")
	alg := fs.String("alg", rs256.AlgRS256, "algorithm; only RS256 is supported")
	bits := fs.Int("bits", rs256.DefaultRSABits, "RSA modulus bits")
	status := fs.String("status", "active", "key status; key generate only supports active")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *alg != rs256.AlgRS256 {
		return fmt.Errorf("only RS256 is supported")
	}
	if *kid == "" {
		return fmt.Errorf("--kid is required")
	}
	if *status != "active" {
		return fmt.Errorf("key generate creates active keys; got --status %q", *status)
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	key, err := env.keys.GenerateActiveKey(context.Background(), *kid, *alg, *bits)
	if err != nil {
		return fmt.Errorf("key generate %q: %w", *kid, err)
	}
	fmt.Printf("kid: %s\nprivate_key: %s\nstatus: %s\n", key.Kid, key.PrivateKeyPath, key.Status)
	return nil
}

func cmdKeyList(args []string) error {
	fs, configPath, dbPath, err := commonFlags("key list", args)
	_ = fs
	if err != nil {
		return err
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	keys, err := env.keys.ListKeys(context.Background())
	if err != nil {
		return fmt.Errorf("key list: %w", err)
	}
	for _, key := range keys {
		fmt.Printf("%s\t%s\t%s\t%s\n", key.Kid, key.Alg, key.Status, key.PrivateKeyPath)
	}
	return nil
}

func cmdUser(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("user requires subcommand")
	}
	switch args[0] {
	case "add":
		return cmdUserAdd(args[1:])
	case "invite":
		return cmdUserInvite(args[1:])
	case "list":
		return cmdUserList(args[1:])
	case "disable":
		return cmdUserDisable(args[1:])
	default:
		return fmt.Errorf("unknown user subcommand %q", args[0])
	}
}

func cmdUserAdd(args []string) error {
	fs, configPath, dbPath, _ := commonFlags("user add", nil)
	provider := fs.String("provider", "google", "identity provider")
	issuer := fs.String("issuer", "https://accounts.google.com", "issuer")
	subject := fs.String("subject", "", "provider subject")
	email := fs.String("email", "", "display email")
	name := fs.String("name", "", "display name")
	emailVerified := fs.Bool("email-verified", false, "email verified")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *subject == "" {
		return fmt.Errorf("--subject is required; use user invite for email pre-registration")
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	u, err := env.core.AddUser(context.Background(), model.AddUserInput{Provider: *provider, Issuer: *issuer, Subject: *subject, Email: *email, EmailVerified: *emailVerified, DisplayName: *name})
	if err != nil {
		return fmt.Errorf("user add %q: %w", *subject, err)
	}
	fmt.Printf("%s\t%s\t%s\n", u.ID, value(u.Email), u.Status)
	return nil
}

func cmdUserInvite(args []string) error {
	fs, configPath, dbPath, _ := commonFlags("user invite", nil)
	provider := fs.String("provider", "google", "identity provider")
	issuer := fs.String("issuer", "https://accounts.google.com", "issuer")
	email := fs.String("email", "", "email address to pre-register")
	name := fs.String("name", "", "display name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" {
		return fmt.Errorf("--email is required")
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	u, err := env.core.AddPreRegisteredUser(context.Background(), model.AddPreRegisteredUserInput{Provider: *provider, Issuer: *issuer, Email: *email, DisplayName: *name})
	if err != nil {
		return fmt.Errorf("user invite %q: %w", *email, err)
	}
	fmt.Printf("%s\t%s\t%s\n", u.ID, value(u.Email), u.Status)
	return nil
}

func cmdUserList(args []string) error {
	fs, configPath, dbPath, err := commonFlags("user list", args)
	_ = fs
	if err != nil {
		return err
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	users, err := env.core.ListUsers(context.Background())
	if err != nil {
		return fmt.Errorf("user list: %w", err)
	}
	for _, u := range users {
		fmt.Printf("%s\t%s\t%s\t%s\n", u.ID, value(u.Email), userSubjectForList(u), u.Status)
	}
	return nil
}

func userSubjectForList(u model.User) string {
	if u.Status == "pending" {
		return ""
	}
	return u.Subject
}

func cmdUserDisable(args []string) error {
	fs, configPath, dbPath, err := commonFlags("user disable", args)
	_ = fs
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: user disable <email-or-id>")
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	if err := env.core.DisableUser(context.Background(), fs.Arg(0)); err != nil {
		return fmt.Errorf("user disable %q: %w", fs.Arg(0), err)
	}
	fmt.Println("disabled")
	return nil
}

func cmdGroup(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("group requires subcommand")
	}
	switch args[0] {
	case "add":
		return cmdGroupAdd(args[1:])
	case "list":
		return cmdGroupList(args[1:])
	case "member":
		return cmdGroupMember(args[1:])
	default:
		return fmt.Errorf("unknown group subcommand %q", args[0])
	}
}

func cmdGroupAdd(args []string) error {
	fs, configPath, dbPath, _ := commonFlags("group add", nil)
	desc := fs.String("description", "", "description")
	pos, err := parseInterspersed(fs, args, map[string]bool{})
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: group add <name>")
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	g, err := env.groups.AddGroup(context.Background(), pos[0], *desc)
	if err != nil {
		return fmt.Errorf("group add %q: %w", pos[0], err)
	}
	fmt.Printf("%s\t%s\n", g.ID, g.Name)
	return nil
}

func cmdGroupList(args []string) error {
	fs, configPath, dbPath, err := commonFlags("group list", args)
	_ = fs
	if err != nil {
		return err
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	groups, err := env.groups.ListGroups(context.Background())
	if err != nil {
		return fmt.Errorf("group list: %w", err)
	}
	for _, g := range groups {
		fmt.Printf("%s\t%s\n", g.ID, g.Name)
	}
	return nil
}

func cmdGroupMember(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("group member requires add or remove")
	}
	fs, configPath, dbPath, err := commonFlags("group member "+args[0], args[1:])
	if err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: group member %s <group> <user-email-or-id>", args[0])
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	switch args[0] {
	case "add":
		err = env.groups.AddGroupMember(context.Background(), fs.Arg(0), fs.Arg(1))
	case "remove":
		err = env.groups.RemoveGroupMember(context.Background(), fs.Arg(0), fs.Arg(1))
	default:
		return fmt.Errorf("unknown group member subcommand %q", args[0])
	}
	if err != nil {
		return err
	}
	fmt.Println("ok")
	return nil
}

func cmdRepo(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("repo requires subcommand")
	}
	switch args[0] {
	case "add":
		return cmdRepoAdd(args[1:])
	case "list":
		return cmdRepoList(args[1:])
	default:
		return fmt.Errorf("unknown repo subcommand %q", args[0])
	}
}

func cmdRepoAdd(args []string) error {
	fs, configPath, dbPath, _ := commonFlags("repo add", nil)
	remote := fs.String("remote", "", "Lore remote URL")
	loreRepoID := fs.String("lore-repository-id", "", "Lore repository id")
	pos, err := parseInterspersed(fs, args, map[string]bool{})
	if err != nil {
		return err
	}
	if len(pos) != 1 || *remote == "" || *loreRepoID == "" {
		return fmt.Errorf("usage: repo add <name> --remote <url> --lore-repository-id <id>")
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	if err := env.core.Upsert(context.Background(), model.Resource{Name: pos[0], RemoteURL: *remote, LoreRepositoryID: *loreRepoID}); err != nil {
		return fmt.Errorf("repo add %q: %w", pos[0], err)
	}
	r, err := env.core.GetByName(context.Background(), pos[0])
	if err != nil {
		return fmt.Errorf("repo add: read created repo %q: %w", pos[0], err)
	}
	fmt.Printf("%s\t%s\t%s\n", r.ID, r.Name, r.LoreRepositoryID)
	return nil
}

func cmdRepoList(args []string) error {
	fs, configPath, dbPath, err := commonFlags("repo list", args)
	_ = fs
	if err != nil {
		return err
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	repos, err := env.core.List(context.Background())
	if err != nil {
		return fmt.Errorf("repo list: %w", err)
	}
	for _, r := range repos {
		fmt.Printf("%s\t%s\t%s\t%s\n", r.ID, r.Name, r.LoreRepositoryID, r.RemoteURL)
	}
	return nil
}

func cmdGrant(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("grant requires subcommand")
	}
	switch args[0] {
	case "add":
		return cmdGrantAdd(args[1:])
	case "list":
		return cmdGrantList(args[1:])
	case "remove":
		return cmdGrantRemove(args[1:])
	default:
		return fmt.Errorf("unknown grant subcommand %q", args[0])
	}
}

func cmdGrantAdd(args []string) error {
	fs, configPath, dbPath, err := commonFlags("grant add", args)
	if err != nil {
		return err
	}
	if fs.NArg() != 3 {
		return fmt.Errorf("usage: grant add <user:email|group:name|service_account:id> <repo> <role>")
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	subType, subID, err := resolveGrantSubject(context.Background(), env.store, fs.Arg(0))
	if err != nil {
		return fmt.Errorf("grant add: resolve subject %q: %w", fs.Arg(0), err)
	}
	g, err := env.grants.AddGrant(context.Background(), subType, subID, fs.Arg(1), fs.Arg(2))
	if err != nil {
		return fmt.Errorf("grant add: subject %q repo %q role %q: %w", fs.Arg(0), fs.Arg(1), fs.Arg(2), err)
	}
	fmt.Printf("%s\t%s:%s\t%s\n", g.ID, g.SubjectType, g.SubjectID, g.Role)
	return nil
}

func cmdGrantList(args []string) error {
	fs, configPath, dbPath, err := commonFlags("grant list", args)
	if err != nil {
		return err
	}
	repo := ""
	if fs.NArg() > 0 {
		repo = fs.Arg(0)
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	grants, err := env.grants.ListGrants(context.Background(), repo)
	if err != nil {
		return fmt.Errorf("grant list repo %q: %w", repo, err)
	}
	for _, g := range grants {
		fmt.Printf("%s\t%s:%s\t%s\t%s\n", g.ID, g.SubjectType, g.SubjectID, g.RepositoryID, g.Role)
	}
	return nil
}

func cmdGrantRemove(args []string) error {
	fs, configPath, dbPath, err := commonFlags("grant remove", args)
	if err != nil {
		return err
	}
	if fs.NArg() != 3 {
		return fmt.Errorf("usage: grant remove <subject> <repo> <role>")
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	subType, subID, err := resolveGrantSubject(context.Background(), env.store, fs.Arg(0))
	if err != nil {
		return fmt.Errorf("grant remove: resolve subject %q: %w", fs.Arg(0), err)
	}
	if err := env.grants.RemoveGrant(context.Background(), subType, subID, fs.Arg(1), fs.Arg(2)); err != nil {
		return fmt.Errorf("grant remove: subject %q repo %q role %q: %w", fs.Arg(0), fs.Arg(1), fs.Arg(2), err)
	}
	fmt.Println("removed")
	return nil
}

func cmdToken(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("token requires subcommand")
	}
	switch args[0] {
	case "mint":
		return cmdTokenMint(args[1:])
	case "mint-authn":
		return cmdTokenMintAuthn(args[1:])
	default:
		return fmt.Errorf("unknown token subcommand %q", args[0])
	}
}

func cmdTokenMintAuthn(args []string) error {
	fs, configPath, dbPath, _ := commonFlags("token mint-authn", nil)
	ttl := fs.Duration("ttl", 0, "authn token TTL; default jwt.ttl_seconds")
	out := fs.String("out", "", "write token to file instead of stdout")
	printCommand := fs.Bool("print-login-command", false, "print lore auth login command to stderr; ignored when --out is set")
	pos, err := parseInterspersed(fs, args, map[string]bool{"print-login-command": true})
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: token mint-authn <user-email-or-id> [--ttl 1h]")
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	res, _, err := env.tokens.MintAuthn(context.Background(), pos[0], *ttl)
	if err != nil {
		return fmt.Errorf("token mint-authn: mint authn for user %q: %w", pos[0], err)
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(res.Token+"\n"), 0o600); err != nil {
			return fmt.Errorf("token mint-authn: write output %q: %w", *out, err)
		}
		fmt.Printf("authn token: %s\n", *out)
	} else {
		fmt.Println(res.Token)
	}
	if shouldPrintLoginCommand(*out, *printCommand) {
		fmt.Fprintf(os.Stderr, "lore auth login --token-type lore --token %s --auth-url %s %s\n", res.Token, env.cfg.Lore.AuthURL, env.cfg.Lore.DefaultRemoteURL)
	}
	return nil
}

func cmdTokenMint(args []string) error {
	fs, configPath, dbPath, _ := commonFlags("token mint", nil)
	role := fs.String("role", "writer", "token role; MVP supports writer")
	ttl := fs.Duration("ttl", 0, "token TTL, e.g. 1h or 15m; default jwt.ttl_seconds")
	out := fs.String("out", "", "write token to file instead of stdout")
	printCommand := fs.Bool("print-login-command", false, "print lore auth login command to stderr; ignored when --out is set")
	pos, err := parseInterspersed(fs, args, map[string]bool{"print-login-command": true})
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: token mint <user-email-or-id> <repo> [--role writer] [--ttl 1h]")
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	res, err := env.tokens.ManualMintAuthz(context.Background(), pos[0], pos[1], *role, *ttl)
	if err != nil {
		return fmt.Errorf("token mint: mint authz for user %q repo %q role %q: %w", pos[0], pos[1], *role, err)
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(res.Token+"\n"), 0o600); err != nil {
			return fmt.Errorf("token mint: write output %q: %w", *out, err)
		}
		fmt.Printf("token: %s\n", *out)
	} else {
		fmt.Println(res.Token)
	}
	if shouldPrintLoginCommand(*out, *printCommand) {
		fmt.Fprintf(os.Stderr, "lore auth login --token-type lore --token %s --auth-url %s %s\n", res.Token, env.cfg.Lore.AuthURL, env.cfg.Lore.DefaultRemoteURL)
	}
	return nil
}

func shouldPrintLoginCommand(out string, requested bool) bool {
	return requested && out == ""
}

func cmdCheck(args []string) error {
	fs, configPath, dbPath, err := commonFlags("check", args)
	if err != nil {
		return err
	}
	if fs.NArg() != 3 {
		return fmt.Errorf("usage: check <user-email-or-id> <repo> <action>")
	}
	env, err := openEnv(*configPath, *dbPath)
	if err != nil {
		return err
	}
	defer env.close()
	user, err := env.core.Resolve(context.Background(), fs.Arg(0))
	if err != nil {
		return fmt.Errorf("check: resolve user %q: %w", fs.Arg(0), err)
	}
	resource, err := env.core.GetByName(context.Background(), fs.Arg(1))
	if err != nil {
		return fmt.Errorf("check: resolve repo %q: %w", fs.Arg(1), err)
	}
	ok, err := env.authz.CanAccess(context.Background(), user.ID, resource.ResourceID, fs.Arg(2))
	if err != nil {
		return fmt.Errorf("check: evaluate user %q repo %q action %q: %w", fs.Arg(0), fs.Arg(1), fs.Arg(2), err)
	}
	if ok {
		fmt.Println("allow")
	} else {
		fmt.Println("deny")
	}
	return nil
}

func resolveGrantSubject(ctx context.Context, st *sqlite.Store, value string) (string, string, error) {
	typ, id, err := subjectParts(value)
	if err != nil {
		return "", "", err
	}
	switch typ {
	case "user":
		u, err := st.ResolveUser(ctx, id)
		if err != nil {
			return "", "", err
		}
		return "user", u.ID, nil
	case "group":
		g, err := st.FindGroupByName(ctx, id)
		if err != nil {
			return "", "", err
		}
		return "group", g.ID, nil
	case "service_account":
		return "service_account", id, nil
	default:
		return "", "", fmt.Errorf("unknown subject type %q", typ)
	}
}

func openStore(path string) (*sqlite.Store, error) {
	st, err := sqlite.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("migrate sqlite: %w", err)
	}
	return st, nil
}

func tokenConfigFromConfig(cfg *config.Config) service.TokenConfig {
	return service.TokenConfig{
		Issuer:              cfg.JWT.Issuer,
		Audience:            cfg.JWT.Audience,
		AuthServiceAudience: stripSchemeAndPort(cfg.Server.PublicBaseURL),
		AuthnTTL:            durationSeconds(cfg.JWT.TTLSeconds),
		AuthzTTL:            15 * time.Minute,
	}
}

func durationSeconds(value int) time.Duration {
	if value == 0 {
		return 0
	}
	return time.Duration(value) * time.Second
}

func stripSchemeAndPort(url string) string {
	if i := strings.Index(url, "://"); i >= 0 {
		url = url[i+3:]
	}
	if i := strings.Index(url, "/"); i >= 0 {
		url = url[:i]
	}
	if h, _, ok := strings.Cut(url, ":"); ok {
		return h
	}
	return url
}

func subjectParts(value string) (string, string, error) {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("want type:id")
	}
	return parts[0], parts[1], nil
}

func parseInterspersed(fs *flag.FlagSet, args []string, boolFlags map[string]bool) ([]string, error) {
	var flagArgs []string
	var pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			pos = append(pos, arg)
			continue
		}
		flagArgs = append(flagArgs, arg)
		name := strings.TrimLeft(arg, "-")
		if idx := strings.Index(name, "="); idx >= 0 {
			name = name[:idx]
		}
		if strings.Contains(arg, "=") || boolFlags[name] {
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			flagArgs = append(flagArgs, args[i+1])
			i++
		}
	}
	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}
	return pos, nil
}

func value(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
