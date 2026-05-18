package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/policysync"
)

// signed-root subcommand flags. Reset between tests via cobra's state model.
var (
	auditRootDir         string
	auditRootPrivKeyPath string
	auditRootIndent      bool
)

var auditRootCmd = &cobra.Command{
	Use:   "signed-root",
	Short: "Emit the current signed Merkle root (JSON) for the RIA generator",
	Long: `Replays the JSONL audit log from --dir, computes the current Merkle root,
optionally signs it with an ed25519 private key from --signer-priv-key (or
$REEF_AUDIT_SIGNER_PRIV_KEY / $REEF_POLICY_SIGNER_PRIV_KEY), and emits a JSON
report:

  {
    "root":       "<hex>",
    "signature":  "<base64 ed25519 sig over the raw root bytes, or empty>",
    "count":      <int>,
    "timestamp":  "<RFC3339 UTC>",
    "dir":        "<audit dir>",
    "signed":     true|false
  }

Used by the Reef Quote RIA generator (A-10) to embed the signed Merkle root
into the RIA PDF's audit-attestation page (page 6). Exit code is 0 when a
non-empty audit log was replayed, even if no signing key was supplied — in
that case the "signature" field is empty and "signed" is false. Exit code is
non-zero only on filesystem / parse errors.

The signing key (if supplied) must be ed25519 PEM (PKCS#8) or raw/seed
base64-encoded, matching the format the policy_sign subcommand uses.`,
	RunE: runAuditSignedRoot,
}

func init() {
	auditCmd.AddCommand(auditRootCmd)

	auditRootCmd.Flags().StringVar(&auditRootDir, "dir", "",
		"Audit log directory (default $REEF_AUDIT_DIR or ./audit)")
	auditRootCmd.Flags().StringVar(&auditRootPrivKeyPath, "signer-priv-key", "",
		"Path to ed25519 private key (default $REEF_AUDIT_SIGNER_PRIV_KEY, "+
			"falling back to $REEF_POLICY_SIGNER_PRIV_KEY). When empty, signature is omitted.")
	auditRootCmd.Flags().BoolVar(&auditRootIndent, "indent", true,
		"Indent JSON output for human reading (default true). Set to false to emit compact JSON for piping.")
}

func runAuditSignedRoot(cmd *cobra.Command, args []string) error {
	dir := auditRootDir
	if dir == "" {
		dir = os.Getenv("REEF_AUDIT_DIR")
	}
	if dir == "" {
		dir = "./audit"
	}

	tree, err := audit.NewTree(dir)
	if err != nil {
		return fmt.Errorf("opening audit tree: %w", err)
	}
	defer tree.Close()

	count, err := tree.Replay()
	if err != nil {
		return fmt.Errorf("replaying audit log: %w", err)
	}

	// Optionally attach a signer. Fail loudly on bad key paths — silent
	// fallback to unsigned output would let A-10's RIA ship without the
	// promised signature, which is a credibility hazard.
	keyPath := auditRootPrivKeyPath
	if keyPath == "" {
		keyPath = os.Getenv("REEF_AUDIT_SIGNER_PRIV_KEY")
	}
	if keyPath == "" {
		keyPath = os.Getenv("REEF_POLICY_SIGNER_PRIV_KEY")
	}
	signed := false
	if keyPath != "" {
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("reading signer private key %q: %w", keyPath, err)
		}
		priv, err := policysync.ParsePrivateKey(keyBytes)
		if err != nil {
			return fmt.Errorf("parsing signer private key: %w", err)
		}
		tree.SetRootSigner(priv)
		signed = true
	}

	root, sig, leafCount, ts := tree.SignedRoot()

	report := map[string]any{
		"root":      root,
		"signature": sig,
		"count":     leafCount,
		"timestamp": ts.UTC().Format("2006-01-02T15:04:05Z07:00"),
		"dir":       dir,
		"signed":    signed && sig != "",
		// Echo whether the replay actually produced any leaves — empty
		// trees are a legitimate (fresh fleet) state, not an error, but the
		// caller (A-10) wants to know.
		"replayed_events": count,
		// Include a hex-encoded leaf domain separator + algorithm tag so a
		// future Go verifier on the RIA PDF can re-derive the root bytes.
		"hash_algo":      "sha256",
		"signature_algo": "ed25519-over-raw-root-bytes",
	}

	out := cmd.OutOrStdout()
	enc := json.NewEncoder(out)
	if auditRootIndent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encoding report: %w", err)
	}
	return nil
}
