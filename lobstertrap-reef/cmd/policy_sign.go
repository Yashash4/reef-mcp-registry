package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/policysync"
)

var (
	policySignOutPath     string
	policySignPrivKeyPath string
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Reef policy tools (sign, verify, distribute)",
}

var policySignCmd = &cobra.Command{
	Use:   "sign <policy-file>",
	Short: "Sign a policy bundle for the Reef policy bus",
	Long: `Reads the policy bundle at <policy-file>, computes a SHA-256 hash, signs the
hash with the operator's ed25519 private key (default $REEF_POLICY_SIGNER_PRIV_KEY
or ./keys/policy-signer.key), and writes the base64-encoded signature to
<policy-file>.sig (or the --output path).

The signature contract is compatible with the cosign-style verification in
pkg/policysync/cosign.go. Operators distribute the policy + signature pair
to the fleet; nodes verify the signature against the bus-rooted public key
before applying the policy.`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicySign,
}

func init() {
	policyCmd.AddCommand(policySignCmd)
	rootCmd.AddCommand(policyCmd)

	policySignCmd.Flags().StringVarP(&policySignOutPath, "output", "o", "",
		"Output path for the signature (default <policy-file>.sig)")
	policySignCmd.Flags().StringVar(&policySignPrivKeyPath, "private-key", "",
		"Path to the ed25519 private key (default $REEF_POLICY_SIGNER_PRIV_KEY or ./keys/policy-signer.key)")
}

func runPolicySign(cmd *cobra.Command, args []string) error {
	policyPath := args[0]
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return fmt.Errorf("reading policy file %q: %w", policyPath, err)
	}

	keyPath := policySignPrivKeyPath
	if keyPath == "" {
		keyPath = os.Getenv("REEF_POLICY_SIGNER_PRIV_KEY")
	}
	if keyPath == "" {
		keyPath = "./keys/policy-signer.key"
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("reading private key %q: %w", keyPath, err)
	}
	priv, err := policysync.ParsePrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("parsing private key: %w", err)
	}

	sigB64, err := policysync.SignBundle(priv, policyBytes)
	if err != nil {
		return fmt.Errorf("signing bundle: %w", err)
	}

	outPath := policySignOutPath
	if outPath == "" {
		outPath = policyPath + ".sig"
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}
	if err := os.WriteFile(outPath, []byte(sigB64), 0644); err != nil {
		return fmt.Errorf("writing signature: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "signed %s -> %s\n", policyPath, outPath)
	return nil
}
