package cmd

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/policysync"
)

var (
	auditVerifyEventID    string
	auditVerifyRoot       string
	auditVerifyDir        string
	auditVerifySignature  string
	auditVerifyPubKeyPath string
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Reef audit tools (Merkle inclusion proofs, signed-root verification)",
	Long:  "Operate on the Reef Merkle audit log to verify inclusion proofs and signed roots.",
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Prove that an event is included in a signed Merkle root",
	Long: `Reads the JSONL audit log from --dir, replays it into an in-memory Merkle
tree, finds the event matching --event-id, builds the inclusion proof, and
asserts that the proof rebuilds the supplied --root.

Exit code 0 means the event is provably included in the signed root.
Non-zero exit means the proof failed — either the event is missing or the
audit log was tampered with.`,
	RunE: runAuditVerify,
}

func init() {
	auditCmd.AddCommand(auditVerifyCmd)
	rootCmd.AddCommand(auditCmd)

	auditVerifyCmd.Flags().StringVar(&auditVerifyEventID, "event-id", "", "Event ID to prove inclusion for (required)")
	auditVerifyCmd.Flags().StringVar(&auditVerifyRoot, "root", "", "Expected Merkle root (hex). If omitted, prints the recomputed root.")
	auditVerifyCmd.Flags().StringVar(&auditVerifyDir, "dir", "", "Audit log directory (default $REEF_AUDIT_DIR or ./audit)")
	auditVerifyCmd.Flags().StringVar(&auditVerifySignature, "signature", "", "Optional base64-encoded signature over the root")
	auditVerifyCmd.Flags().StringVar(&auditVerifyPubKeyPath, "signer-pub-key", "", "Optional path to an ed25519 public key for verifying --signature")
	_ = auditVerifyCmd.MarkFlagRequired("event-id")
}

func runAuditVerify(cmd *cobra.Command, args []string) error {
	dir := auditVerifyDir
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
	if count == 0 {
		return fmt.Errorf("audit log at %q is empty", dir)
	}

	idx, ev, err := tree.FindEvent(auditVerifyEventID)
	if err != nil {
		return fmt.Errorf("finding event %q: %w", auditVerifyEventID, err)
	}

	proof, leafHash, err := tree.InclusionProof(idx)
	if err != nil {
		return fmt.Errorf("building inclusion proof: %w", err)
	}

	recomputedRoot := tree.Root()
	if auditVerifyRoot != "" {
		if err := audit.VerifyInclusionProof(leafHash, proof, auditVerifyRoot); err != nil {
			return fmt.Errorf("inclusion proof failed: %w", err)
		}
	}

	// Optional signature verification.
	if auditVerifySignature != "" {
		if auditVerifyPubKeyPath == "" {
			return fmt.Errorf("--signature requires --signer-pub-key")
		}
		pubBytes, err := os.ReadFile(auditVerifyPubKeyPath)
		if err != nil {
			return fmt.Errorf("reading signer pub key: %w", err)
		}
		pub, err := policysync.ParsePublicKey(pubBytes)
		if err != nil {
			return fmt.Errorf("parsing signer pub key: %w", err)
		}
		rootHex := auditVerifyRoot
		if rootHex == "" {
			rootHex = recomputedRoot
		}
		if err := audit.VerifySignedRoot(rootHex, auditVerifySignature, ed25519.PublicKey(pub)); err != nil {
			return fmt.Errorf("signed-root verification failed: %w", err)
		}
	}

	report := map[string]any{
		"event_id":         ev.EventID,
		"leaf_index":       idx,
		"leaf_hash":        hex.EncodeToString(leafHash),
		"recomputed_root":  recomputedRoot,
		"expected_root":    auditVerifyRoot,
		"proof_length":     len(proof),
		"event_action":     ev.Action,
		"event_request_id": ev.RequestID,
		"event_timestamp":  ev.Timestamp,
		"verified":         true,
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
