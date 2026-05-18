// Package audit Merkle tree extensions for tamper-evident audit log.
//
// Reef stores every action verdict (ALLOW/DENY/MODIFY/REDIRECT/QUARANTINE/
// HUMAN_REVIEW/BIND_DENIED) as a leaf in an append-only Merkle tree. The
// tree's signed root is exported periodically (default every 60s) and on
// shutdown. The RIA PDF (Layer 7) embeds the signed root, giving an
// underwriter cryptographic proof that the audit log has not been tampered
// with.
//
// Implementation notes:
//   - Hash function: SHA-256.
//   - Leaf hash: SHA-256(0x00 || serialized event JSON). The 0x00 domain
//     separator follows RFC 6962 to prevent second-preimage attacks across
//     leaf vs internal node hashes.
//   - Internal hash: SHA-256(0x01 || left || right).
//   - Persistence: every leaf is appended to a JSONL file under REEF_AUDIT_DIR.
//     On startup, Replay() reads the file and rebuilds the tree so a process
//     restart doesn't lose tamper-evidence.
//   - Root signing: optional; SetRootSigner attaches an ed25519 private key
//     and SignedRoot returns the root + signature.
//
// Concurrency: Append uses an internal mutex so concurrent pipeline calls
// are safe. The Merkle layer cache rebuilds on every Append in O(log n);
// for v1's expected event volumes (a few thousand per day) this is fine.
package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// cryptoRandRead is split out so tests can stub randomness deterministically.
func cryptoRandRead(p []byte) (int, error) {
	return rand.Read(p)
}

// AuditEvent is the canonical leaf payload.
//
// BodyTruncated is set to true when the source body exceeded
// defaults.AuditBodyTruncationBytes and was clipped before BodyHash was
// computed. Verifier tooling reads this field to decide whether to compare
// hashes byte-for-byte (BodyTruncated == false) or only as a "first-N-bytes
// match" (BodyTruncated == true). Refinement R-B6 (Phase B Round 1 Batch B)
// added this field — older trees without the field default to false, which
// is the safe interpretation for legacy leaves under the old 4 KiB cap.
type AuditEvent struct {
	EventID       string    `json:"event_id"`
	Timestamp     time.Time `json:"timestamp"`
	Direction     string    `json:"direction"` // "ingress" or "egress"
	RequestID     string    `json:"request_id"`
	AgentID       string    `json:"agent_id,omitempty"`
	SVIDSubject   string    `json:"svid_subject,omitempty"`
	RuleID        string    `json:"rule_id,omitempty"`
	Action        string    `json:"action"`
	DenyMsg       string    `json:"deny_message,omitempty"`
	BodyHash      string    `json:"body_hash,omitempty"`
	BodyTruncated bool      `json:"body_truncated,omitempty"`
	Metadata      any       `json:"metadata,omitempty"`
}

// Errors returned by the Merkle layer.
var (
	ErrTreeEmpty       = errors.New("merkle: tree is empty")
	ErrEventNotFound   = errors.New("merkle: event not found")
	ErrProofMismatch   = errors.New("merkle: inclusion proof does not produce expected root")
	ErrInvalidIndex    = errors.New("merkle: leaf index out of range")
	ErrSignatureFailed = errors.New("merkle: signing the root failed")
)

// Tree is the in-memory Merkle tree. Constructed via NewTree.
type Tree struct {
	mu sync.Mutex

	leaves     []leaf
	rootSigner ed25519.PrivateKey
	persistDir string
	jsonlFile  *os.File
}

type leaf struct {
	Event AuditEvent
	Hash  []byte
}

// NewTree builds an empty in-memory Merkle tree. If persistDir is non-empty
// the tree opens (or creates) "events.jsonl" in that dir for append-only
// persistence. Replay() can later read the file to rebuild the tree.
func NewTree(persistDir string) (*Tree, error) {
	t := &Tree{}
	if persistDir == "" {
		return t, nil
	}
	if err := os.MkdirAll(persistDir, 0755); err != nil {
		return nil, fmt.Errorf("merkle: mkdir %q: %w", persistDir, err)
	}
	jsonlPath := filepath.Join(persistDir, "events.jsonl")
	f, err := os.OpenFile(jsonlPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("merkle: open %q: %w", jsonlPath, err)
	}
	t.persistDir = persistDir
	t.jsonlFile = f
	return t, nil
}

// SetRootSigner attaches an ed25519 private key used by SignedRoot to sign
// the current Merkle root. May be called before or after any Appends.
func (t *Tree) SetRootSigner(priv ed25519.PrivateKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rootSigner = priv
}

// Close flushes pending state and closes the persistence file.
func (t *Tree) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.jsonlFile == nil {
		return nil
	}
	err := t.jsonlFile.Close()
	t.jsonlFile = nil
	return err
}

// Append adds an event as a new leaf. Returns the leaf's hex-encoded hash.
// If the event's EventID is empty, Append generates one of the form
// "ev-<32-hex>". If the event's Timestamp is zero, Append sets it to now.
func (t *Tree) Append(ev AuditEvent) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if ev.EventID == "" {
		ev.EventID = newEventID()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	canonical, err := canonicalJSON(ev)
	if err != nil {
		return "", fmt.Errorf("merkle: canonical encode: %w", err)
	}
	h := leafHash(canonical)
	t.leaves = append(t.leaves, leaf{Event: ev, Hash: h})

	if t.jsonlFile != nil {
		if _, err := t.jsonlFile.Write(append(canonical, '\n')); err != nil {
			// Persistence failure is not fatal to the in-memory tree, but we
			// surface it so operators see disk problems before the next
			// signed-root export reveals nothing on disk.
			return hex.EncodeToString(h), fmt.Errorf("merkle: persist leaf: %w", err)
		}
		_ = t.jsonlFile.Sync()
	}
	return hex.EncodeToString(h), nil
}

// Replay loads events from the persisted JSONL file (if any) into the tree.
// Existing in-memory leaves are reset to keep replay deterministic.
func (t *Tree) Replay() (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.persistDir == "" {
		return 0, nil
	}
	path := filepath.Join(t.persistDir, "events.jsonl")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("merkle: open replay file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return 0, fmt.Errorf("merkle: read replay file: %w", err)
	}
	t.leaves = t.leaves[:0]
	count := 0
	for _, line := range bytesSplitNewlines(data) {
		if len(line) == 0 {
			continue
		}
		var ev AuditEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return count, fmt.Errorf("merkle: malformed leaf at line %d: %w", count+1, err)
		}
		canonical, err := canonicalJSON(ev)
		if err != nil {
			return count, fmt.Errorf("merkle: canonical encode during replay: %w", err)
		}
		h := leafHash(canonical)
		t.leaves = append(t.leaves, leaf{Event: ev, Hash: h})
		count++
	}
	return count, nil
}

// Root returns the current root hash (hex-encoded). Returns "" for an empty
// tree.
func (t *Tree) Root() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.leaves) == 0 {
		return ""
	}
	return hex.EncodeToString(t.rootLocked())
}

// Count returns the current leaf count.
func (t *Tree) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.leaves)
}

// SignedRoot returns (hex-root, base64-signature, count, exportedAt).
// If no signer is configured the signature field is "".
func (t *Tree) SignedRoot() (string, string, int, time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now().UTC()
	if len(t.leaves) == 0 {
		return "", "", 0, now
	}
	r := t.rootLocked()
	rootHex := hex.EncodeToString(r)
	if t.rootSigner == nil || len(t.rootSigner) != ed25519.PrivateKeySize {
		return rootHex, "", len(t.leaves), now
	}
	sig := ed25519.Sign(t.rootSigner, r)
	return rootHex, base64.StdEncoding.EncodeToString(sig), len(t.leaves), now
}

// rootLocked computes the root over the current leaves. MUST be called with
// t.mu held.
func (t *Tree) rootLocked() []byte {
	level := make([][]byte, len(t.leaves))
	for i, lf := range t.leaves {
		level[i] = lf.Hash
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				// RFC 6962-style: odd nodes are promoted directly rather than
				// hashing with themselves. This avoids confusion between trees
				// of size N and 2N where the last element repeats.
				next = append(next, level[i])
				continue
			}
			next = append(next, internalHash(level[i], level[i+1]))
		}
		level = next
	}
	return level[0]
}

// InclusionProof returns the audit path for the leaf at index i. Each entry
// is (sibling-hash, is-right-sibling) so the verifier knows whether to hash
// (sibling || running) or (running || sibling). The result can be fed to
// VerifyInclusionProof.
type ProofStep struct {
	SiblingHash []byte
	IsRight     bool // true if sibling is on the right (running hash is on the left)
}

// InclusionProof returns the proof + leaf hash for the leaf at index i.
func (t *Tree) InclusionProof(i int) ([]ProofStep, []byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.leaves) == 0 {
		return nil, nil, ErrTreeEmpty
	}
	if i < 0 || i >= len(t.leaves) {
		return nil, nil, ErrInvalidIndex
	}
	level := make([][]byte, len(t.leaves))
	for k, lf := range t.leaves {
		level[k] = lf.Hash
	}
	leafHashCopy := append([]byte(nil), level[i]...)
	var proof []ProofStep
	idx := i
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for k := 0; k < len(level); k += 2 {
			if k+1 == len(level) {
				// Lone-promoted node.
				next = append(next, level[k])
				continue
			}
			next = append(next, internalHash(level[k], level[k+1]))
		}
		if idx == len(level)-1 && len(level)%2 == 1 {
			// Promoted; no sibling at this level. idx is now next.last.
			idx = len(next) - 1
			level = next
			continue
		}
		sibling := idx ^ 1
		isRight := sibling > idx
		proof = append(proof, ProofStep{
			SiblingHash: append([]byte(nil), level[sibling]...),
			IsRight:     isRight,
		})
		idx /= 2
		level = next
	}
	return proof, leafHashCopy, nil
}

// FindEvent returns the index and a copy of the AuditEvent matching eventID,
// or ErrEventNotFound.
func (t *Tree) FindEvent(eventID string) (int, AuditEvent, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, lf := range t.leaves {
		if lf.Event.EventID == eventID {
			return i, lf.Event, nil
		}
	}
	return 0, AuditEvent{}, ErrEventNotFound
}

// VerifyInclusionProof rebuilds the root from a leaf hash + proof and
// compares it against the expected root.
func VerifyInclusionProof(leafHash []byte, proof []ProofStep, expectedRootHex string) error {
	running := append([]byte(nil), leafHash...)
	for _, step := range proof {
		if step.IsRight {
			running = internalHash(running, step.SiblingHash)
		} else {
			running = internalHash(step.SiblingHash, running)
		}
	}
	got := hex.EncodeToString(running)
	if !strings.EqualFold(got, expectedRootHex) {
		return fmt.Errorf("%w: got %s, want %s", ErrProofMismatch, got, expectedRootHex)
	}
	return nil
}

// VerifySignedRoot checks that the base64 signature was produced by the given
// ed25519 public key over the (decoded) root hash.
func VerifySignedRoot(rootHex string, sigB64 string, pub ed25519.PublicKey) error {
	root, err := hex.DecodeString(rootHex)
	if err != nil {
		return fmt.Errorf("merkle: invalid root hex: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("merkle: invalid signature base64: %w", err)
	}
	if !ed25519.Verify(pub, root, sig) {
		return ErrSignatureFailed
	}
	return nil
}

// leafHash domain-separates leaves from internal nodes.
func leafHash(canonical []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(canonical)
	sum := h.Sum(nil)
	return sum
}

// internalHash combines two child hashes.
func internalHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// canonicalJSON serialises the event with sorted keys so leaf hashes are
// reproducible across versions of Go's encoding/json. encoding/json already
// emits struct field keys in declaration order; we go further by marshalling
// through a map sort to defend against future struct-field reordering.
func canonicalJSON(ev AuditEvent) ([]byte, error) {
	first, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(first, &m); err != nil {
		return nil, err
	}
	return marshalSortedMap(m)
}

// marshalSortedMap serialises a map with deterministically-sorted keys.
func marshalSortedMap(m map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []byte
	out = append(out, '{')
	for i, k := range keys {
		if i > 0 {
			out = append(out, ',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		out = append(out, kb...)
		out = append(out, ':')
		var vb []byte
		switch v := m[k].(type) {
		case map[string]any:
			vb, err = marshalSortedMap(v)
		default:
			vb, err = json.Marshal(v)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, vb...)
	}
	out = append(out, '}')
	return out, nil
}

// newEventID returns a "ev-<32-hex>" event identifier. Uses crypto/rand so
// IDs are unguessable; the prefix makes them visually distinct from request
// IDs (which are "req-N") and quarantine IDs ("q-...").
func newEventID() string {
	var b [16]byte
	if _, err := readRand(b[:]); err != nil {
		return fmt.Sprintf("ev-fallback-%d", time.Now().UnixNano())
	}
	return "ev-" + hex.EncodeToString(b[:])
}

// readRand wraps crypto/rand.Read so it can be stubbed in tests.
var readRand = func(p []byte) (int, error) {
	return cryptoRandRead(p)
}

// bytesSplitNewlines splits on '\n' without allocating per-line strings.
func bytesSplitNewlines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
