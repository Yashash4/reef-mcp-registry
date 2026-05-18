// Reef A-7 — policy applier for the gRPC bus client hot-reload path.
//
// When a verified SignedBundle arrives via the bus, the gRPC client hands
// the YAML bytes to this applier. The applier parses the YAML, validates
// it, and atomically swaps the live policy on the running pipeline.
//
// Fail-closed contract: any parse/validation error is returned to the
// client, which acks "policy_parse_failed" and KEEPS the previous policy
// active. The pipeline never falls back to a permissive default.
//
// We deliberately do NOT touch the policy YAML file on disk — the gRPC
// bus is the source of truth for the running policy; a fresh restart
// re-loads the file-on-disk policy and then the bus catches it back up.

package cmd

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/engine/actions"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
)

// PolicyApplier is the concrete implementation of policysync.PolicyApplier.
// It hot-swaps the GuardRules + Network section of the live policy struct
// when a verified bundle arrives.
//
// Concurrency: a single sync.Mutex serialises swaps. Readers (the pipeline)
// read fields without locking because Go's policy struct is read-after-Load
// pattern — the pipeline takes a fresh snapshot per request. For v1 this
// is sufficient; v2 will introduce an atomic pointer swap for stricter
// memory ordering.
type PolicyApplier struct {
	logger actions.Logger
	mu     sync.Mutex
	pol    *policy.Policy

	// applied counts successful hot-reloads (exposed for tests).
	applied int

	// onApply is an optional hook tests use to observe the swap.
	onApply func(version string)
}

func newPolicyApplier(pol *policy.Policy, logger actions.Logger) *PolicyApplier {
	return &PolicyApplier{
		logger: logger,
		pol:    pol,
	}
}

// SetOnApply registers a callback fired after a successful hot-reload.
// Used by integration tests to detect propagation.
func (a *PolicyApplier) SetOnApply(fn func(version string)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onApply = fn
}

// AppliedCount returns the number of successful hot-reloads.
func (a *PolicyApplier) AppliedCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.applied
}

// Apply parses the bundle YAML and hot-swaps the live policy fields. The
// pipeline reads the new fields on the next ingress/egress evaluation.
func (a *PolicyApplier) Apply(_ context.Context, bundleID, version string, yamlBytes []byte) error {
	if len(yamlBytes) == 0 {
		return fmt.Errorf("policy_apply: bundle %s has empty YAML", bundleID)
	}
	tmpPath, err := writeTempYAML(yamlBytes)
	if err != nil {
		return fmt.Errorf("policy_apply: write temp yaml: %w", err)
	}
	defer os.Remove(tmpPath)

	pol, err := policy.LoadFromFile(tmpPath)
	if err != nil {
		return fmt.Errorf("policy_apply: parse: %w", err)
	}

	a.mu.Lock()
	a.pol.Version = pol.Version
	a.pol.PolicyName = pol.PolicyName
	a.pol.DefaultAction = pol.DefaultAction
	a.pol.IngressRules = pol.IngressRules
	a.pol.EgressRules = pol.EgressRules
	a.pol.RateLimits = pol.RateLimits
	a.pol.Network = pol.Network
	a.pol.Filesystem = pol.Filesystem
	a.pol.Notifications = pol.Notifications
	a.pol.Reef = pol.Reef
	a.applied++
	hook := a.onApply
	a.mu.Unlock()

	a.logger.Info("policy hot-reloaded from bus",
		"bundle_id", bundleID,
		"version", version,
		"ingress_rules", len(pol.IngressRules),
		"egress_rules", len(pol.EgressRules),
	)
	if hook != nil {
		hook(version)
	}
	return nil
}

// writeTempYAML writes the bundle bytes to a temp file so policy.LoadFromFile
// (which only takes a path) can parse it. We could refactor LoadFromFile to
// take a reader, but this is a smaller surface change.
func writeTempYAML(b []byte) (string, error) {
	f, err := os.CreateTemp("", "reef-bus-bundle-*.yaml")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, werr := f.Write(b); werr != nil {
		_ = os.Remove(f.Name())
		return "", werr
	}
	return f.Name(), nil
}

// envOrDefault returns env[key] or fallback if unset/empty.
func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
