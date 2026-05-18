package cmd

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/dashboard"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/defaults"
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
	serveCmd.Flags().StringVar(&listenAddr, "listen", defaults.DefaultListenAddr, "Address to listen on")
	serveCmd.Flags().StringVar(&backendURL, "backend", defaults.DefaultBackendURL, "Backend LLM server URL")
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

	// Shared root context for long-running background goroutines (Merkle
	// signed-root export, gRPC policy bus client, dashboard). Cancelled on
	// SIGINT/SIGTERM so every goroutine drops cleanly during shutdown.
	// Refinement R-B4 (Phase B): the Merkle ticker goroutine now consumes
	// this ctx so it stops emitting on shutdown.
	rootCtx, stopRootCtx := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopRootCtx()

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
			redirectFallback = defaults.DefaultRedirectFallback
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
			registryURL = defaults.DefaultMCPRegistryURL
		}
		registryTimeout := defaults.MCPRegistryRequestTimeout
		if v := os.Getenv("REEF_MCP_REGISTRY_TIMEOUT_MS"); v != "" {
			if ms, perr := strconv.Atoi(v); perr == nil && ms > 0 {
				registryTimeout = time.Duration(ms) * time.Millisecond
			}
		}
		verifier := mcpsupply.NewHTTPVerifier(registryURL, registryTimeout)
		pipe = pipe.WithMCPVerifier(verifier)

		// Reef A-6: SVID JWT identity verification.
		//
		// Refinement R-B3 (Phase B): when `pol.Reef.RequireSVID == true` we
		// MUST fail-closed at boot if the verifier cannot be built. The
		// previous behaviour logged a warning and continued silently — a
		// misconfigured production node would then allow every
		// unauthenticated agent through. Boot-time fail-closed is the only
		// honest behaviour here.
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
		svidVerifier, svidWired, sErr := buildSVIDVerifier(svidKeysDir, svidAudience)
		if pol.Reef.RequireSVID {
			if !svidWired {
				return fmt.Errorf(
					"reef: policy.reef.require_svid=true but SVID verifier could not be constructed: %w (issuer_keys_dir=%q audience=%q) — refusing to boot in fail-OPEN mode",
					sErr, svidKeysDir, svidAudience,
				)
			}
			logger.Info().
				Strs("svid_issuer_keys", svidVerifier.KeyIDs()).
				Str("svid_audience", svidAudience).
				Bool("require_svid", true).
				Msg("SVID verifier enabled (fail-closed boot)")
			pipe = pipe.WithSVIDVerifier(svidVerifier)
		} else if svidWired {
			pipe = pipe.WithSVIDVerifier(svidVerifier)
			logger.Info().
				Strs("svid_issuer_keys", svidVerifier.KeyIDs()).
				Str("svid_audience", svidAudience).
				Msg("SVID verifier enabled")
		} else {
			logger.Warn().Err(sErr).Str("dir", svidKeysDir).
				Msg("SVID verifier disabled — operator action required for production (require_svid=false)")
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
			// Refinement R-B4: respect rootCtx so we drop cleanly on SIGTERM
			// instead of leaking on shutdown.
			interval := time.Duration(pol.Reef.Audit.SignRootIntervalSeconds) * time.Second
			if interval <= 0 {
				interval = defaults.MerkleSignedRootInterval
			}
			merkleLogger := logger.With().Str("subsystem", "merkle-root-export").Logger()
			go runMerkleSignedRootExport(rootCtx, merkle, interval, merkleLogger)
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
			busURL = defaults.DefaultPolicyBusGRPCURL
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
						FleetID:     envOrDefault("REEF_FLEET_ID", defaults.DefaultFleetID),
						RegionID:    envOrDefault("REEF_REGION_ID", defaults.DefaultRegionID),
						SiteID:      envOrDefault("REEF_SITE_ID", defaults.DefaultSiteID),
						NodeID:      envOrDefault("REEF_NODE_ID", defaults.DefaultNodeID),
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
						// Refinement R-B4: bus client respects rootCtx so a
						// shutdown signal terminates the long-lived stream.
						busLogger := logger.With().Str("subsystem", "policysync").Logger()
						go func() {
							if rerr := busClient.Run(rootCtx); rerr != nil && !errors.Is(rerr, context.Canceled) {
								busLogger.Warn().Err(rerr).Msg("policy bus client exited")
							} else {
								busLogger.Info().Msg("policy bus client shutting down on context cancel")
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
		dashboard.Run(rootCtx, hub)

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

	// Refinement R-B1 (Phase B): replace bare http.ListenAndServe with a
	// fully-configured http.Server. ReadHeaderTimeout closes the Slowloris
	// header-feed attack window; ReadTimeout / WriteTimeout / IdleTimeout
	// bound the per-connection lifetime so a stalled client can't tie up the
	// listener indefinitely.
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: defaults.HTTPReadHeaderTimeout,
		ReadTimeout:       defaults.HTTPReadTimeout,
		WriteTimeout:      defaults.HTTPWriteTimeout,
		IdleTimeout:       defaults.HTTPIdleTimeout,
	}

	// Run ListenAndServe in a goroutine so the main goroutine can block on
	// signal delivery; any non-graceful listener exit is surfaced via errCh.
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		close(errCh)
	}()

	// Block until either the listener errors out OR a shutdown signal
	// arrives. Graceful shutdown gets GracefulShutdownTimeout to drain
	// in-flight requests before the listener is forcibly closed.
	select {
	case err := <-errCh:
		stopRootCtx() // notify background goroutines that we're going down
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	case <-rootCtx.Done():
		logger.Info().Msg("shutdown signal received — draining in-flight requests")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), defaults.GracefulShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Warn().Err(err).Msg("graceful shutdown timed out — forcing close")
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		logger.Info().Msg("graceful shutdown complete")
		return nil
	}
}

// buildSVIDVerifier attempts to construct an SVID JWT verifier from the
// configured issuer-keys directory. Returns (verifier, true, nil) on success
// or (nil, false, reason) when the dir is missing/empty/unloadable. Caller
// decides whether the failure is fatal (R-B3: it IS fatal when
// policy.reef.require_svid == true).
func buildSVIDVerifier(dir, audience string) (*identity.JWTVerifier, bool, error) {
	if dir == "" {
		return nil, false, errors.New("svid: issuer keys directory not configured")
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		return nil, false, fmt.Errorf("svid: cannot stat issuer keys directory %q: %w", dir, statErr)
	}
	v, err := identity.NewJWTVerifier(identity.VerifierConfig{
		ExpectedAudience: audience,
		IssuerKeysDir:    dir,
	})
	if err != nil {
		return nil, false, fmt.Errorf("svid: verifier construction failed: %w", err)
	}
	if len(v.KeyIDs()) == 0 {
		return nil, false, fmt.Errorf("svid: no issuer keys loaded from %q", dir)
	}
	return v, true, nil
}

// runMerkleSignedRootExport ticks once per interval and writes the signed
// root snapshot to the structured logger. Stops cleanly on ctx.Done().
// Refinement R-B4 (Phase B Round 1 Batch B) replaced the bare
// `for range ticker.C` loop with this cancellable variant.
func runMerkleSignedRootExport(ctx context.Context, tree *audit.Tree, interval time.Duration, logger zerolog.Logger) {
	if interval <= 0 {
		interval = defaults.MerkleSignedRootInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	logger.Info().Dur("interval", interval).Msg("merkle signed-root export started")
	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("merkle-signed-root-export shutting down")
			return
		case <-ticker.C:
			root, sig, count, _ := tree.SignedRoot()
			if root == "" {
				continue
			}
			logger.Info().
				Str("root", root).
				Str("signature", sig).
				Int("count", count).
				Msg("merkle signed root export")
		}
	}
}
