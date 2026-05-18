package cmd

import (
	"context"
	"crypto/ed25519"
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
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/identity"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/mcpsupply"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/otel"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/policysync"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/ratelimit"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/session"
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

		// Reef A-6: SVID JWT identity verification.
		svidKeysDir := pol.Reef.SVIDIssuerKeysDir
		if svidKeysDir == "" {
			svidKeysDir = os.Getenv("REEF_SVID_ISSUER_KEYS_DIR")
		}
		if svidKeysDir == "" {
			svidKeysDir = "./keys/svid-issuers"
		}
		svidAudience := pol.Reef.SVIDAudience
		if svidAudience == "" {
			svidAudience = "lobstertrap-reef"
		}
		if _, statErr := os.Stat(svidKeysDir); statErr == nil {
			svidVerifier, sErr := identity.NewJWTVerifier(identity.VerifierConfig{
				ExpectedAudience: svidAudience,
				IssuerKeysDir:    svidKeysDir,
			})
			if sErr != nil {
				logger.Warn().Err(sErr).Str("dir", svidKeysDir).Msg("SVID verifier disabled — operator action required for production")
			} else {
				pipe = pipe.WithSVIDVerifier(svidVerifier)
				logger.Info().
					Strs("svid_issuer_keys", svidVerifier.KeyIDs()).
					Str("svid_audience", svidAudience).
					Msg("SVID verifier enabled")
			}
		} else {
			logger.Warn().Str("dir", svidKeysDir).Msg("SVID issuer keys dir missing — SVID verifier disabled")
		}

		// Reef A-6: per-identity rate limiter.
		rl := pol.Reef.RateLimit
		if rl.RatePerSecond > 0 && rl.Burst > 0 {
			lim, rErr := ratelimit.New(ratelimit.Config{
				Rate:  rl.RatePerSecond,
				Burst: rl.Burst,
			})
			if rErr != nil {
				logger.Warn().Err(rErr).Msg("rate limiter disabled")
			} else {
				pipe = pipe.WithRateLimiter(lim)
				logger.Info().
					Float64("rate_per_sec", rl.RatePerSecond).
					Int("burst", rl.Burst).
					Msg("per-identity rate limiter enabled")
			}
		}

		// Reef A-6: EWMA ASI category tracker.
		ew := pol.Reef.EWMA
		if ew.Alpha > 0 && len(ew.Categories) > 0 {
			tracker, eErr := session.NewTracker(session.TrackerConfig{
				Alpha:      ew.Alpha,
				Categories: ew.Categories,
			})
			if eErr != nil {
				logger.Warn().Err(eErr).Msg("EWMA tracker disabled")
			} else {
				pipe = pipe.WithEWMATracker(tracker)
				logger.Info().
					Float64("alpha", ew.Alpha).
					Strs("categories", ew.Categories).
					Float64("threshold", ew.Threshold).
					Msg("EWMA ASI tracker enabled")
			}
		}

		// Reef A-6: Merkle audit tree.
		auditDir := pol.Reef.Audit.Dir
		if auditDir == "" {
			auditDir = os.Getenv("REEF_AUDIT_DIR")
		}
		if auditDir == "" {
			auditDir = "./audit"
		}
		merkle, mErr := audit.NewTree(auditDir)
		if mErr != nil {
			logger.Warn().Err(mErr).Str("dir", auditDir).Msg("Merkle audit tree disabled")
		} else {
			if pol.Reef.Audit.SignerKeyPath != "" {
				keyBytes, kErr := os.ReadFile(pol.Reef.Audit.SignerKeyPath)
				if kErr == nil {
					if priv, pErr := policysync.ParsePrivateKey(keyBytes); pErr == nil {
						merkle.SetRootSigner(ed25519.PrivateKey(priv))
					} else {
						logger.Warn().Err(pErr).Msg("Merkle root signer parse failed")
					}
				} else {
					logger.Warn().Err(kErr).Msg("Merkle root signer read failed")
				}
			}
			if replayed, rErr := merkle.Replay(); rErr != nil {
				logger.Warn().Err(rErr).Msg("Merkle replay failed — tree starts empty")
			} else if replayed > 0 {
				logger.Info().Int("leaves", replayed).Msg("Merkle audit tree replayed from disk")
			}
			pipe = pipe.WithMerkleTree(merkle)
			logger.Info().Str("dir", auditDir).Msg("Merkle audit tree enabled")

			// Periodic signed root export every reef.audit.sign_root_interval_seconds.
			interval := pol.Reef.Audit.SignRootIntervalSeconds
			if interval <= 0 {
				interval = 60
			}
			go func() {
				ticker := time.NewTicker(time.Duration(interval) * time.Second)
				defer ticker.Stop()
				for range ticker.C {
					root, sig, count, _ := merkle.SignedRoot()
					if root == "" {
						continue
					}
					logger.Info().
						Str("root", root).
						Str("signature", sig).
						Int("count", count).
						Msg("merkle signed root export")
				}
			}()
		}

		// Reef A-6: OpenTelemetry exporter.
		otelKind := pol.Reef.Otel.Exporter
		if otelKind == "" {
			otelKind = os.Getenv("REEF_OTEL_EXPORTER")
		}
		if otelKind == "" {
			otelKind = "stdout"
		}
		otelEndpoint := pol.Reef.Otel.Endpoint
		if otelEndpoint == "" {
			otelEndpoint = os.Getenv("REEF_OTEL_ENDPOINT")
		}
		exp, oErr := otel.New(otel.Config{
			Kind:        otel.ExporterKind(otelKind),
			Endpoint:    otelEndpoint,
			ServiceName: "lobstertrap-reef",
			Insecure:    true,
		})
		if oErr != nil {
			logger.Warn().Err(oErr).Str("kind", otelKind).Msg("OTel exporter degraded — falling back to no-op")
		}
		pipe = pipe.WithOTelExporter(exp)
		logger.Info().Str("exporter", string(exp.Kind())).Msg("OpenTelemetry exporter enabled")

		// Reef A-7: gRPC policy bus client. Opens a long-lived Subscribe
		// stream against the bus and hot-reloads the active policy on each
		// verified bundle. Fails closed: a tampered bundle leaves the
		// previous policy active (the client acks "verify_failed" so the
		// bus dashboard surfaces the rejection).
		busURL := os.Getenv("REEF_POLICY_BUS_GRPC_URL")
		if busURL == "" {
			busURL = pol.Reef.PolicyBus.GRPCURL
		}
		if busURL == "" {
			busURL = "localhost:50051"
		}
		if pol.Reef.PolicySignerPubKey != "" || os.Getenv("REEF_POLICY_BUS_DISABLE") == "" {
			signerPubKey := pol.Reef.PolicySignerPubKey
			if signerPubKey == "" {
				signerPubKey = os.Getenv("REEF_POLICY_SIGNER_PUB_KEY")
			}
			if signerPubKey == "" {
				logger.Warn().Msg("policy bus client disabled — REEF_POLICY_SIGNER_PUB_KEY unset and reef.policy_signer_pub_key empty")
			} else if _, statErr := os.Stat(signerPubKey); statErr != nil {
				logger.Warn().Err(statErr).Str("path", signerPubKey).Msg("policy bus client disabled — signer public key not readable")
			} else {
				busVerifier, vErr := policysync.NewCosignVerifier(signerPubKey)
				if vErr != nil {
					logger.Warn().Err(vErr).Msg("policy bus client disabled — verifier construction failed")
				} else {
					identity := policysync.NodeIdentity{
						FleetID:     envOrDefault("REEF_FLEET_ID", "demo-fleet"),
						RegionID:    envOrDefault("REEF_REGION_ID", "demo-region"),
						SiteID:      envOrDefault("REEF_SITE_ID", "demo-site"),
						NodeID:      envOrDefault("REEF_NODE_ID", "node-1"),
						SVIDSubject: os.Getenv("REEF_SVID_SUBJECT"),
					}
					policyApplier := newPolicyApplier(pol, &reefLoggerAdapter{logger: logger.With().Str("subsystem", "policy-apply").Logger()})
					initialBackoff := time.Duration(pol.Reef.PolicyBus.RetryBackoffSeconds.Initial * float64(time.Second))
					maxBackoff := time.Duration(pol.Reef.PolicyBus.RetryBackoffSeconds.Max * float64(time.Second))
					busClient, cErr := policysync.NewClient(policysync.Config{
						Endpoint:       busURL,
						Identity:       identity,
						Verifier:       busVerifier,
						Applier:        policyApplier,
						Logger:         &reefLoggerAdapter{logger: logger.With().Str("subsystem", "policysync").Logger()},
						InitialBackoff: initialBackoff,
						MaxBackoff:     maxBackoff,
					})
					if cErr != nil {
						logger.Warn().Err(cErr).Msg("policy bus client construction failed — proceeding without hot reload")
					} else {
						go func() {
							if rerr := busClient.Run(context.Background()); rerr != nil && rerr != context.Canceled {
								logger.Warn().Err(rerr).Msg("policy bus client exited")
							}
						}()
						logger.Info().
							Str("bus_url", busURL).
							Str("fleet", identity.FleetID).
							Str("region", identity.RegionID).
							Str("site", identity.SiteID).
							Str("node", identity.NodeID).
							Msg("policy bus client subscribed")
					}
				}
			}
		}

		logger.Info().
			Str("quarantine_dir", store.Dir()).
			Str("redirect_fallback", redirectFallback).
			Str("human_review_webhook", pol.Notifications.HumanReviewWebhook).
			Str("mcp_registry_url", registryURL).
			Dur("mcp_registry_timeout", registryTimeout).
			Bool("require_svid", pol.Reef.RequireSVID).
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
