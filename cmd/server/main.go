// Command server is the proxy-manager control plane: an HTTP API that owns the
// sing-box process, the nftables TPROXY ruleset, and the node store.
//
// Runs as a systemd unit on bare-metal Raspberry Pi OS -- not in Docker. It
// needs CAP_NET_ADMIN to load the ruleset (AmbientCapabilities=CAP_NET_ADMIN or
// User=root) and it manages sing-box as a child process.
//
// Shutdown ordering is the important part of this file: on SIGTERM the HTTP
// server drains, then the nftables rules come down, then sing-box stops. Exiting
// with rules loaded and no engine listening would blackhole every LAN client
// until someone SSHed in, so that path is handled explicitly rather than left to
// the process dying.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"proxy-manager/internal/api"
	"proxy-manager/internal/engine"
	"proxy-manager/internal/netfilter"
	"proxy-manager/internal/store"
	"proxy-manager/internal/tester"
)

// repeatable collects a flag given more than once (-sub a -sub b) and also
// accepts one comma-separated value, since systemd unit files are easier to
// write that way.
type repeatable []string

func (r *repeatable) String() string { return strings.Join(*r, ",") }

func (r *repeatable) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*r = append(*r, part)
		}
	}
	return nil
}

type config struct {
	listen      string
	token       string
	storePath   string
	statePath   string
	configPath  string
	cachePath   string
	singBox     string
	scriptsDir  string
	subs        repeatable
	clashAPI    string
	clashSecret string
	tproxyPort  int
	logLevel    string
	probeURL    string
	concurrency int
	timeout     time.Duration
	exposeCreds bool
	noRestore   bool
}

func main() {
	cfg := parseFlags()

	log := newLogger(cfg.logLevel)
	slog.SetDefault(log)

	if err := run(cfg, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.listen, "listen", ":8080", "HTTP listen address for the API")
	flag.StringVar(&cfg.token, "token", os.Getenv("PROXY_MANAGER_TOKEN"),
		"bearer token required on /api routes (env PROXY_MANAGER_TOKEN); empty disables auth")
	flag.StringVar(&cfg.storePath, "store", "/var/lib/proxy-manager/nodes.json",
		"node store file")
	flag.StringVar(&cfg.statePath, "state", "/var/lib/proxy-manager/state.json",
		"operator state file (proxy on/off, selected node)")
	flag.StringVar(&cfg.configPath, "config", "/etc/proxy-manager/singbox/config.json",
		"generated sing-box config path")
	flag.StringVar(&cfg.cachePath, "cache", "/var/lib/proxy-manager/cache.db",
		"sing-box cache_file path; also persists the node selection across restarts")
	flag.StringVar(&cfg.singBox, "sing-box", "sing-box", "sing-box binary path or name on PATH")
	flag.StringVar(&cfg.scriptsDir, "scripts", "",
		"directory holding apply.sh/remove.sh/tproxy.conf; empty probes standard locations")
	flag.Var(&cfg.subs, "sub",
		"subscription URL or file path; repeatable, or comma-separated (env PROXY_MANAGER_SUBS)")
	flag.StringVar(&cfg.clashAPI, "clash-api", "127.0.0.1:9090",
		"sing-box Clash API listen address; required to switch nodes without a restart, empty disables")
	flag.StringVar(&cfg.clashSecret, "clash-secret", os.Getenv("PROXY_MANAGER_CLASH_SECRET"),
		"bearer token for the sing-box Clash API (env PROXY_MANAGER_CLASH_SECRET)")
	flag.IntVar(&cfg.tproxyPort, "tproxy-port", engine.DefaultTProxyPort,
		"TPROXY inbound port; must match TPROXY_PORT in tproxy.conf")
	flag.StringVar(&cfg.logLevel, "log-level", "info", "debug|info|warn|error")
	flag.StringVar(&cfg.probeURL, "probe-url", tester.DefaultProbeURL, "latency probe target")
	flag.IntVar(&cfg.concurrency, "probe-concurrency", 4,
		"parallel latency probes; each is its own sing-box process, so keep it low on a Pi")
	flag.DurationVar(&cfg.timeout, "refresh-timeout", 10*time.Minute,
		"budget for one refresh job: fetch, parse, latency sweep, engine reload")
	flag.BoolVar(&cfg.exposeCreds, "expose-credentials", false,
		"include UUIDs and passwords in GET /api/nodes responses")
	flag.BoolVar(&cfg.noRestore, "no-restore", false,
		"do not re-enable the proxy at startup even if it was enabled at last shutdown")
	flag.Parse()

	if len(cfg.subs) == 0 {
		if env := os.Getenv("PROXY_MANAGER_SUBS"); env != "" {
			_ = cfg.subs.Set(env)
		}
	}
	return cfg
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	// Text to stderr: journald captures it and the output stays greppable.
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

func run(cfg config, log *slog.Logger) error {
	// Signal handling is installed before anything is started, so a SIGTERM
	// arriving during startup is still honoured rather than killing the process
	// with a half-loaded ruleset.
	rootCtx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	nodeStore, err := store.Open(cfg.storePath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	log.Info("store loaded", "path", nodeStore.Path(), "nodes", nodeStore.Len())

	fw, err := netfilter.New(cfg.scriptsDir)
	if err != nil {
		return fmt.Errorf("netfilter: %w", err)
	}

	// svcRef is needed by the engine's OnExit hook, which is wired before the
	// Service exists. The hook only fires once the engine has been started,
	// which cannot happen before New returns below.
	var svcRef *api.Service
	eng := engine.NewManager(engine.Options{
		BinaryPath:     cfg.singBox,
		ConfigPath:     cfg.configPath,
		TProxyPort:     cfg.tproxyPort,
		CacheFilePath:  cfg.cachePath,
		ClashAPIListen: cfg.clashAPI,
		ClashAPISecret: cfg.clashSecret,
		LogLevel:       cfg.logLevel,
		Logger:         log.With("src", "engine"),
		OnExit: func(err error) {
			if svcRef != nil {
				svcRef.HandleEngineExit(err)
			}
		},
	})

	lat, err := tester.New(tester.Options{
		BinaryPath:  cfg.singBox,
		ProbeURL:    cfg.probeURL,
		Concurrency: cfg.concurrency,
		Attempts:    2, // two attempts: one lost packet should not mark a node dead
		Logger:      log.With("src", "tester"),
	}, engine.RenderOutbound)
	if err != nil {
		return fmt.Errorf("tester: %w", err)
	}

	svc, err := api.New(api.Config{
		Store:            nodeStore,
		Engine:           eng,
		Firewall:         fw,
		Tester:           lat,
		Selector:         api.NewClashClient(eng.ClashAPIAddr(), eng.ClashAPISecret()),
		SubscriptionURLs: cfg.subs,
		StatePath:        cfg.statePath,
		RefreshTimeout:   cfg.timeout,
		Logger:           log.With("src", "api"),
	})
	if err != nil {
		return fmt.Errorf("api service: %w", err)
	}
	svcRef = svc

	warnIfExposed(cfg, log)
	if len(cfg.subs) == 0 {
		log.Warn("no subscription URLs configured; POST /api/nodes/refresh will fail until -sub is set")
	}
	if cfg.clashAPI == "" {
		log.Warn("clash api disabled; POST /api/proxy/select cannot switch nodes on a running engine")
	}

	srv := &http.Server{
		Addr: cfg.listen,
		Handler: api.NewRouter(svc, api.RouterOptions{
			Token:             cfg.token,
			ExposeCredentials: cfg.exposeCreds,
			Logger:            log.With("src", "http"),
		}),
		// Generous write timeout: a refresh returns immediately, but Status can
		// wait on a loopback call into the engine.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Bind before restoring the proxy so a port clash fails fast, without having
	// started an engine and loaded a ruleset that then has to be torn down.
	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.listen, err)
	}

	if cfg.noRestore {
		log.Info("skipping state restore (-no-restore)")
	} else if err := svc.Restore(rootCtx); err != nil {
		// Non-fatal by design: if the proxy cannot come back up, the API still
		// has to serve so an operator can find out why.
		log.Error("could not restore previous proxy state; API is still available", "err", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("api listening", "addr", ln.Addr().String(),
			"auth", cfg.token != "", "subscriptions", len(cfg.subs),
			"dashboard", dashboardURL(ln.Addr().String()))
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		if err != nil {
			// The listener died on its own; still tear down engine and rules.
			shutdown(svc, srv, log)
			return fmt.Errorf("http server: %w", err)
		}
	case <-rootCtx.Done():
		log.Info("signal received; shutting down")
		// Restore default signal handling so a second Ctrl-C / SIGTERM during a
		// slow teardown kills the process instead of being swallowed.
		stop()
		shutdown(svc, srv, log)
	}
	return nil
}

// shutdown drains HTTP, then tears down the gateway in the safe order.
func shutdown(svc *api.Service, srv *http.Server, log *slog.Logger) {
	// A fresh context: the root one is already cancelled, and teardown still has
	// to run to completion.
	httpCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(httpCtx); err != nil {
		log.Warn("http server did not drain cleanly; forcing close", "err", err)
		_ = srv.Close()
	}

	// Longer budget than HTTP: this removes the nftables ruleset and stops
	// sing-box (SIGTERM, escalating to SIGKILL after the engine's StopTimeout).
	// Getting this wrong leaves the LAN blackholed, so it is worth the wait.
	svcCtx, cancelSvc := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancelSvc()
	if err := svc.Shutdown(svcCtx); err != nil {
		log.Error("unclean shutdown; verify with "+
			"`nft list table inet proxy_tproxy` and remove it by hand if present", "err", err)
		return
	}
	log.Info("shutdown complete: tproxy rules removed, engine stopped")
}

// dashboardURL renders a clickable address for the embedded UI. A wildcard bind
// is reported as loopback: "http://[::]:8080" is not a URL anyone can open.
func dashboardURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr + "/"
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/"
}

// warnIfExposed flags an unauthenticated control plane reachable off-host. These
// endpoints load firewall rules and start a process holding every proxy
// credential in the store, so a silent default is not acceptable.
func warnIfExposed(cfg config, log *slog.Logger) {
	if cfg.token != "" {
		return
	}
	host, _, err := net.SplitHostPort(cfg.listen)
	if err != nil {
		host = cfg.listen
	}
	loopback := false
	switch host {
	case "localhost":
		loopback = true
	case "", "0.0.0.0", "::", "[::]":
		loopback = false
	default:
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			loopback = ip.IsLoopback()
		}
	}
	if loopback {
		return
	}
	log.Warn("API is listening off-host with NO authentication: anyone who can "+
		"reach it can start/stop interception and read node metadata. "+
		"Set -token (or PROXY_MANAGER_TOKEN), or bind 127.0.0.1 and front it with NPM.",
		"listen", cfg.listen)
}
