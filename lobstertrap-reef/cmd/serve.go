package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/dashboard"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/engine/actions"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/pipeline"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/proxy"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/quarantine"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/mcpsupply"
)

// reefLoggerAdapter bridges actions.Logger over zerolog so action handlers
// emit structured events into the same log stream as the rest of the proxy.
type reefLoggerAdapter struct{ logger zerolog.Logger }

func (a *reefLoggerAdapter) Warn(msg string, kv ...any) {
	a.logger.Warn().Interface("kv", kvSlice(kv)).Msg(msg)
}

func (a *reefLoggerAdapter) Info(msg string, kv ...any) {
	a.logger.Info().Interface("kv", kvSlice(kv)).Msg(msg)
}

func (a *reefLoggerAdapter) Error(msg string, err error, kv ...any) {
	a.logger.Error().Err(err).Interface("kv", kvSlice(kv)).Msg(msg)
}

// kvSlice reshapes the variadic kv pairs into a slice of (key,value)
// strings; zerolog handles the structured emit. Defensive against odd-length
// inputs — a stray key without a value is rendered as `<no-value>`.
func kvSlice(kv []any) []string {
	out := make([]string, 0, len(kv))
	for i := 0; i < len(kv); i += 2 {
		k := fmt.Sprintf("%v", kv[i])
		v := "<no-value>"
		if i+1 < len(kv) {
			v = fmt.Sprintf("%v", kv[i+1])
		}
		out = append(out, k+"="+v)
	}
	return out
}

var (
	policyFile  string
	listenAddr  string
	backendURL  string
	auditFile   string
	noDashboard bool
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Lobster Trap reverse proxy",
	Long:  "Start the HTTP reverse proxy that inspects prompts and responses using deep prompt inspection.",
	RunE:  runServe,
}

func init() {
	serveCmd.Flags().StringVar(&policyFile, "policy", "configs/default_policy.yaml", "Path to policy YAML file")
	serveCmd.Flags().StringVar(&listenAddr, "listen", ":8080", "Address to listen on")
	serveCmd.Flags().StringVar(&backendURL, "backend", "http://localhost:11434", "Backend LLM server URL")
	serveCmd.Flags().StringVar(&auditFile, "audit-log", "", "Path to audit log file (default: stderr)")
	serveCmd.Flags().BoolVar(&noDashboard, "no-dashboard", false, "Disable the real-time dashboard")
}

func runServe(cmd *cobra.Command, args []string) error {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().Timestamp().Str("component", "lobstertrap").Logger()

	// Load policy
	pol, err := policy.LoadFromFile(policyFile)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}
	logger.Info().
		Str("policy", pol.PolicyName).
		Str("version", pol.Version).
		Int("ingress_rules", len(pol.IngressRules)).
		Int("egress_rules", len(pol.EgressRules)).
		Msg("policy loaded")

	// Set up audit logger
	var auditLogger *audit.Logger
	if auditFile != "" {
		auditLogger, err = audit.NewFileLogger(auditFile)
		if err != nil {
			return fmt.Errorf("creating audit logger: %w", err)
		}
		logger.Info().Str("path", auditFile).Msg("audit log enabled")
	} else {
		auditLogger = audit.NewStderrLogger()
	}

	// Create pipeline. When --enable-reef is on, build the action dispatcher
	// + quarantine store and wire them. When off, fall back to the upstream
	// pipeline.New path so vanilla Lobster Trap behaviour is preserved.
	var pipe *pipeline.Pipeline
	if EnableReef {
		quarantineDir := os.Getenv("REEF_QUARANTINE_DIR")
		store, qerr := quarantine.NewStore(quarantineDir)
		if qerr != nil {
			return fmt.Errorf("creating quarantine store: %w", qerr)
		}
		redirectFallback := os.Getenv("REEF_REDIRECT_TARGET")
		if redirectFallback == "" {
			redirectFallback = "http://localhost:8765/gemma-stub"
		}
		// If the policy YAML didn't set the webhook, pick it up from the env.
		if pol.Notifications.HumanReviewWebhook == "" {
			if v := os.Getenv("REEF_HUMAN_REVIEW_WEBHOOK"); v != "" {
				pol.Notifications.HumanReviewWebhook = v
			}
		}
		dispatcher, derr := actions.NewDispatcher(actions.DispatcherConfig{
			Policy:           pol,
			Store:            store,
			Logger:           &reefLoggerAdapter{logger: logger.With().Str("subsystem", "reef-actions").Logger()},
			RedirectFallback: redirectFallback,
		})
		if derr != nil {
			return fmt.Errorf("creating reef action dispatcher: %w", derr)
		}
		pipe = pipeline.NewWithReef(pol, auditLogger, dispatcher, true)

		// Reef A-5: attach the MCP signature registry verifier so the
		// pre-ingress hook blocks unsigned / poisoned MCP server binds.
		// REEF_MCP_REGISTRY_URL defaults to the Atlas service's docker-compose
		// hostname; tests + local runs can point it at http://localhost:8080.
		registryURL := os.Getenv("REEF_MCP_REGISTRY_URL")
		if registryURL == "" {
			registryURL = "http://localhost:8080"
		}
		registryTimeout := 1500 * time.Millisecond
		if v := os.Getenv("REEF_MCP_REGISTRY_TIMEOUT_MS"); v != "" {
			if ms, perr := strconv.Atoi(v); perr == nil && ms > 0 {
				registryTimeout = time.Duration(ms) * time.Millisecond
			}
		}
		verifier := mcpsupply.NewHTTPVerifier(registryURL, registryTimeout)
		pipe = pipe.WithMCPVerifier(verifier)

		logger.Info().
			Str("quarantine_dir", store.Dir()).
			Str("redirect_fallback", redirectFallback).
			Str("human_review_webhook", pol.Notifications.HumanReviewWebhook).
			Str("mcp_registry_url", registryURL).
			Dur("mcp_registry_timeout", registryTimeout).
			Msg("reef extensions enabled")
	} else {
		pipe = pipeline.New(pol, auditLogger)
		logger.Info().Msg("reef extensions disabled (vanilla Lobster Trap)")
	}

	// Create proxy
	guardProxy, err := proxy.New(pipe, backendURL, logger)
	if err != nil {
		return fmt.Errorf("creating proxy: %w", err)
	}

	// Set up the HTTP handler — either with dashboard mux or proxy-only
	var handler http.Handler = guardProxy

	if !noDashboard {
		hub := dashboard.NewHub(pol)
		pipe.AddObserver(hub.OnEvent)
		dashboard.Run(context.Background(), hub)

		dashHandler := dashboard.Handler(hub)
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/_lobstertrap") {
				dashHandler.ServeHTTP(w, r)
				return
			}
			guardProxy.ServeHTTP(w, r)
		})
	}

	logger.Info().
		Str("listen", listenAddr).
		Str("backend", backendURL).
		Msg("starting lobster trap proxy")

	fmt.Fprintf(os.Stderr, "\n  Lobster Trap v%s\n", Version)
	fmt.Fprintf(os.Stderr, "  Policy:  %s (%s)\n", pol.PolicyName, pol.Version)
	fmt.Fprintf(os.Stderr, "  Listen:  %s\n", listenAddr)
	fmt.Fprintf(os.Stderr, "  Backend: %s\n", backendURL)
	if !noDashboard {
		dashAddr := listenAddr
		if strings.HasPrefix(dashAddr, ":") {
			dashAddr = "localhost" + dashAddr
		}
		fmt.Fprintf(os.Stderr, "  Dashboard: http://%s/_lobstertrap/\n", dashAddr)
	}
	fmt.Fprintln(os.Stderr)

	return http.ListenAndServe(listenAddr, handler)
}
