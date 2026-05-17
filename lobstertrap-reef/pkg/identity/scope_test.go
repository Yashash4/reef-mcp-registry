package identity

import (
	"math"
	"testing"
)

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

func TestIntentMismatch(t *testing.T) {
	tests := []struct {
		name     string
		declared Scope
		detected DetectedIntent
		want     float64
	}{
		{
			name: "perfect_match",
			declared: Scope{
				DeclaredIntent:  "data_access",
				DeclaredTools:   []string{"docs.read", "summary.write"},
				DeclaredDomains: []string{"intra.corp"},
			},
			detected: DetectedIntent{
				IntentCategory: "data_access",
				Tools:          []string{"docs.read", "summary.write"},
				Domains:        []string{"intra.corp"},
			},
			want: 0.0,
		},
		{
			name: "complete_disjoint",
			declared: Scope{
				DeclaredIntent:  "code_execution",
				DeclaredTools:   []string{"shell.exec"},
				DeclaredDomains: []string{"intra.corp"},
			},
			detected: DetectedIntent{
				IntentCategory: "communication",
				Tools:          []string{"send_message"},
				Domains:        []string{"attacker.example.com"},
			},
			want: 1.0,
		},
		{
			name: "partial_tools_overlap",
			declared: Scope{
				DeclaredIntent:  "data_access",
				DeclaredTools:   []string{"docs.read", "summary.write"},
				DeclaredDomains: []string{"intra.corp"},
			},
			detected: DetectedIntent{
				IntentCategory: "data_access",
				// Intersection={docs.read} ∪={docs.read, summary.write, send_message}
				// Jaccard distance = 1 - 1/3 = 0.6666...
				Tools:   []string{"docs.read", "send_message"},
				Domains: []string{"intra.corp"},
			},
			// 1/3 * 0 + 1/3 * (2/3) + 1/3 * 0  ≈ 0.2222
			want: 1.0 / 3.0 * (2.0 / 3.0),
		},
		{
			name: "empty_detected_means_no_mismatch",
			declared: Scope{
				DeclaredIntent:  "data_access",
				DeclaredTools:   []string{"docs.read"},
				DeclaredDomains: []string{"intra.corp"},
			},
			detected: DetectedIntent{}, // DPI saw nothing actionable
			// Empty detected on every axis ⇒ DPI couldn't see what the agent
			// is doing yet, so we score 0 (not a mismatch — just no activity).
			want: 0.0,
		},
		{
			name:     "both_empty_scores_zero",
			declared: Scope{},
			detected: DetectedIntent{},
			want:     0.0,
		},
		{
			name: "domain_drift_only",
			declared: Scope{
				DeclaredIntent:  "data_access",
				DeclaredTools:   []string{"docs.read"},
				DeclaredDomains: []string{"intra.corp"},
			},
			detected: DetectedIntent{
				IntentCategory: "data_access",
				Tools:          []string{"docs.read"},
				Domains:        []string{"attacker.example.com"},
			},
			// Intent matches, tools match, domains fully disjoint
			want: 1.0 / 3.0,
		},
		{
			name: "declared_intent_synonym_matches",
			declared: Scope{
				DeclaredIntent:  "read+summarize",
				DeclaredTools:   []string{"docs.read"},
				DeclaredDomains: []string{"intra.corp"},
			},
			detected: DetectedIntent{
				IntentCategory: "data_access", // synonym envelope contains "read" + "summarize"
				Tools:          []string{"docs.read"},
				Domains:        []string{"intra.corp"},
			},
			want: 0.0,
		},
		{
			name: "case_and_whitespace_insensitive",
			declared: Scope{
				DeclaredIntent:  "data_access",
				DeclaredTools:   []string{"Docs.Read ", " Summary.Write"},
				DeclaredDomains: []string{"Intra.Corp"},
			},
			detected: DetectedIntent{
				IntentCategory: "data_access",
				Tools:          []string{"docs.read", "summary.write"},
				Domains:        []string{"intra.corp"},
			},
			want: 0.0,
		},
		{
			name: "intent_mismatch_only",
			declared: Scope{
				DeclaredIntent:  "data_access",
				DeclaredTools:   []string{"docs.read"},
				DeclaredDomains: []string{"intra.corp"},
			},
			detected: DetectedIntent{
				IntentCategory: "code_execution", // not in data_access synonym envelope
				Tools:          []string{"docs.read"},
				Domains:        []string{"intra.corp"},
			},
			want: 1.0 / 3.0,
		},
		{
			name: "general_detected_does_not_flag",
			declared: Scope{
				DeclaredIntent:  "data_access",
				DeclaredTools:   []string{"docs.read"},
				DeclaredDomains: []string{"intra.corp"},
			},
			detected: DetectedIntent{
				IntentCategory: "general",
				Tools:          []string{"docs.read"},
				Domains:        []string{"intra.corp"},
			},
			want: 0.0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IntentMismatch(tc.declared, tc.detected)
			if !almostEqual(got, tc.want) {
				t.Errorf("IntentMismatch=%v want %v", got, tc.want)
			}
			if got < 0 || got > 1 {
				t.Errorf("score %v out of [0,1]", got)
			}
		})
	}
}

func TestJaccardDistance(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
		want float64
	}{
		{"identical", []string{"a", "b"}, []string{"a", "b"}, 0},
		{"disjoint", []string{"a"}, []string{"b"}, 1},
		{"half_overlap", []string{"a", "b"}, []string{"b", "c"}, 1.0 / 3.0 * 2}, // 1-1/3
		{"both_empty", nil, nil, 0},
		{"one_empty", []string{"a"}, nil, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := jaccardDistance(normaliseSet(tc.a), normaliseSet(tc.b))
			if !almostEqual(got, tc.want) {
				t.Errorf("jaccardDistance=%v want %v", got, tc.want)
			}
		})
	}
}
