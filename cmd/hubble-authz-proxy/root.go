package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/puzzle/hubble-authz-proxy/internal/authz"
	"github.com/puzzle/hubble-authz-proxy/internal/authz/rbac"
	"github.com/puzzle/hubble-authz-proxy/internal/identity"
	"github.com/puzzle/hubble-authz-proxy/internal/logging"
	"github.com/puzzle/hubble-authz-proxy/internal/metrics"
	"github.com/puzzle/hubble-authz-proxy/internal/proxy"
	"github.com/puzzle/hubble-authz-proxy/internal/registry"
)

// config holds every flag. A struct rather than the individual *string/*bool
// locals flag.Parse populated: cobra/pflag write straight into named fields via
// *Var, so there is no reason to route through pointers-to-locals as the
// stdlib flag idiom did.
type config struct {
	listen, metricsListen, backendURL, apiPrefix, identityPfx string
	mode, mapFile, logLevel, logFormat                        string
	mapReload, rbacTTL, channelTTL, shutdownGrace             time.Duration
	rbacWorkers, maxChannels                                  int
	maxResponse                                               int64
	rbacWatch, reqBoth, notifyEmpty                           bool
}

// newRootCmd builds the CLI. Flag long names are byte-identical to the
// pre-cobra flag package ones, so the Helm chart's rendered --args need no
// change. What does change: pflag only accepts the double-dash form, where
// stdlib flag accepted single-dash long flags too — see the README note next
// to --rbac-watch.
func newRootCmd() *cobra.Command {
	var cfg config

	cmd := &cobra.Command{
		Use:   "hubble-authz-proxy",
		Short: "Namespace-scoped authorization proxy for the Hubble UI",
		Long: "hubble-authz-proxy sits between the Hubble UI frontend and its unmodified\n" +
			"backend, filtering namespace-scoped data out of responses the caller may not\n" +
			"see. Authentication is expected to be terminated upstream; this process only\n" +
			"does authorization.",
		Version: version,
		Args:    cobra.NoArgs,
		// A runtime failure (bad backend URL, authorizer that can't start, the
		// listener dying) is reported through the structured logger below, not by
		// dumping command usage — that's only useful for a flag mistake, which
		// pflag already reports on its own before RunE ever runs.
		SilenceUsage: true,
		RunE: func(*cobra.Command, []string) error {
			return run(cfg)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&cfg.listen, "listen", ":8090", "address the Hubble UI frontend proxies /api to")
	flags.StringVar(&cfg.metricsListen, "metrics-listen", ":9090", "address serving /metrics and /healthz; empty disables it")
	flags.StringVar(&cfg.backendURL, "backend", "http://hubble-ui-backend:8090", "upstream hubble-ui backend base URL")
	flags.StringVar(&cfg.apiPrefix, "api-prefix", "/api", "path prefix carrying backend routes; everything else is passed through")
	flags.StringVar(&cfg.identityPfx, "identity-header-prefix", identity.AuthRequestPrefix,
		"header family carrying the caller identity: X-Auth-Request (nginx auth_request / Traefik forwardAuth) or X-Forwarded (oauth2-proxy as the reverse proxy)")
	flags.StringVar(&cfg.mode, "authz", "static", "authorization backend: static | rbac")
	flags.StringVar(&cfg.mapFile, "authz-config", "/etc/hubble-authz/mapping.yaml", "static mode: group/user -> namespace mapping")
	flags.DurationVar(&cfg.mapReload, "authz-config-reload", 30*time.Second, "static mode: how often to re-read the mapping file; 0 disables and makes changes need a pod restart")
	flags.DurationVar(&cfg.rbacTTL, "rbac-ttl", 60*time.Second, "rbac mode: cache TTL for a caller's resolved namespace set")
	flags.IntVar(&cfg.rbacWorkers, "rbac-concurrency", 16, "rbac mode: SubjectAccessReviews issued in parallel per resolution")
	flags.BoolVar(&cfg.rbacWatch, "rbac-watch", true,
		"rbac mode: watch Namespaces/Roles/ClusterRoles/RoleBindings/ClusterRoleBindings to evict a "+
			"caller's cached scope sooner than --rbac-ttl when access changes; falls back to TTL-only "+
			"if the ServiceAccount lacks watch permission (never fatal)")
	flags.DurationVar(&cfg.channelTTL, "channel-ttl", 10*time.Minute, "how long to keep per-channel service-map state after a client goes idle")
	flags.IntVar(&cfg.maxChannels, "max-channels", registry.DefaultMaxChannels, "cap on client channels holding service-map state; the least recently used is dropped past this")
	flags.BoolVar(&cfg.reqBoth, "require-both-endpoints", false, "only show traffic when BOTH endpoints are in allowed namespaces (stricter)")
	flags.DurationVar(&cfg.shutdownGrace, "shutdown-timeout", 20*time.Second, "how long to let in-flight requests finish after SIGTERM")
	flags.Int64Var(&cfg.maxResponse, "max-response-bytes", 8<<20,
		"largest backend response the proxy will buffer to filter. The whole body is held in memory, so peak usage is roughly this times the number of concurrent callers; oversized responses are refused, never forwarded unfiltered")
	flags.BoolVar(&cfg.notifyEmpty, "notify-empty-scope", true, "tell a caller with no visible namespaces why the UI is empty, via the NoPermission notification hubble-ui renders in its Status Center")
	flags.StringVar(&cfg.logLevel, "log-level", "info", "debug | info | warn | error. debug logs the identity and resolved scope of every request")
	flags.StringVar(&cfg.logFormat, "log-format", "text", "text | json")

	return cmd
}

// run is everything the old main() did after flag.Parse(): build the
// authorizer, wire the proxy, serve, drain on SIGTERM. Unchanged in substance
// from before the cobra move, just reading cfg fields instead of flag pointers.
func run(cfg config) error {
	logger := logging.New(cfg.logLevel, cfg.logFormat)
	slog.SetDefault(logger)

	backend, err := url.Parse(cfg.backendURL)
	if err != nil {
		logger.Error("cannot parse --backend", "value", cfg.backendURL, "err", err)
		os.Exit(1)
	}
	if backend.Scheme == "" || backend.Host == "" {
		logger.Error("--backend must be an absolute URL", "value", cfg.backendURL)
		os.Exit(1)
	}

	// Cancelled on SIGTERM/SIGINT. Kubernetes sends SIGTERM and then removes the
	// pod from Service endpoints, so draining matters here: the UI holds long
	// poll requests open, and killing them mid-flight surfaces as errors in the
	// browser during every rollout.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	var authorizer authz.Authorizer
	switch cfg.mode {
	case "static":
		var staticAuthz *authz.StaticAuthorizer
		staticAuthz, err = authz.NewStaticAuthorizer(cfg.mapFile, logger)
		if err == nil {
			go staticAuthz.RunReloader(ctx, cfg.mapReload)
			authorizer = staticAuthz
		}
	case "rbac":
		var rbacAuthz *rbac.Authorizer
		rbacAuthz, err = rbac.New(cfg.rbacTTL, cfg.rbacWorkers)
		if err == nil {
			go rbacAuthz.RunSweeper(ctx)
			if cfg.rbacWatch {
				go rbacAuthz.RunWatch(ctx, logger)
			}
			authorizer = rbacAuthz
		}
	default:
		err = errors.New("unknown --authz mode (want static|rbac)")
	}
	if err != nil {
		logger.Error("cannot start authorizer", "mode", cfg.mode, "err", err)
		os.Exit(1)
	}
	authorizer = authz.Instrumented(authorizer, cfg.mode)

	reg := registry.New(cfg.channelTTL, cfg.maxChannels)
	go reg.RunSweeper(ctx)

	handler := proxy.New(backend, authorizer, reg, cfg.apiPrefix, cfg.reqBoth, cfg.identityPfx, cfg.maxResponse, cfg.notifyEmpty, logger)

	srv := &http.Server{
		Addr:              cfg.listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	var metricsSrv *http.Server
	if cfg.metricsListen != "" {
		metricsSrv = &http.Server{
			Addr:              cfg.metricsListen,
			Handler:           metrics.Handler(metrics.NewRegistry(version, proxy.KnownRoutes)),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("metrics listener stopped", "err", err)
			}
		}()
	}

	logger.Info("starting",
		"version", version,
		"listen", cfg.listen,
		"metrics", cfg.metricsListen,
		"backend", backend.String(),
		"authz", cfg.mode,
		"mappingReload", cfg.mapReload.String(),
		"requireBothEndpoints", cfg.reqBoth,
		"identityHeaders", cfg.identityPfx+"-*",
		"maxResponseBytes", cfg.maxResponse,
		"maxChannels", cfg.maxChannels,
		"notifyEmptyScope", cfg.notifyEmpty,
		"rbacWatch", cfg.rbacWatch,
		"logLevel", cfg.logLevel)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("serve failed", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		logger.Info("signal received, draining", "timeout", cfg.shutdownGrace.String())
	}

	// Detached from ctx, which is already cancelled by the signal.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.shutdownGrace)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("proxy shutdown", "err", err)
	}
	if metricsSrv != nil {
		if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
			logger.Error("metrics shutdown", "err", err)
		}
	}
	logger.Info("stopped")
	return nil
}
