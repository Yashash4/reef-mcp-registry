# Reef — `go test -race` Verification

> Refinement R-B7 (Phase B Round 1 Batch B). POV-5 (FAANG senior engineer)
> flagged that the previous "race-clean by construction" claim was made
> without an actual `-race` run because the `gcc` toolchain wasn't
> installed. This document captures the green run on the verified host.

## Status

- **Date:** 2026-05-18
- **Host:** WSL2 Ubuntu 24.04.x on Windows 11 (Linux 5.15.167.4-microsoft-standard-WSL2 x86_64)
- **Toolchain:** `go1.23.4 linux/amd64`, `gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`
- **CGO_ENABLED:** `1` (mandatory for the race detector)
- **Command:** `make test-race`  →  `CGO_ENABLED=1 go test -race -count=1 ./... 2>&1 | tee race-test.log`
- **Result:** **17 packages tested, 14 with tests, 0 with race detections, 0 failures.**

## Canonical green output

```
?       github.com/Yashash4/reef-mcp-registry/lobstertrap-reef  [no test files]
?       github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/dashboard       [no test files]
?       github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/defaults        [no test files]
ok      github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/cmd      1.393s
ok      github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit   1.099s
ok      github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/engine/actions  1.281s
ok      github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/inspector       1.434s
ok      github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/metadata        1.060s
?       github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/policysync/proto     [no test files]
ok      github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/pipeline        2.515s
ok      github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy  1.163s
ok      github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/proxy   1.117s
ok      github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/quarantine      1.160s
ok      github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/identity     1.098s
ok      github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/mcpsupply    1.406s
ok      github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/otel 1.028s
ok      github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/policysync   1.478s
ok      github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/ratelimit    1.321s
ok      github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/session      1.017s
```

## Race-prone paths actively exercised

The race detector is only as informative as the tests that hit the
race-prone code. The following hot paths have dedicated concurrent tests
that fail under `-race` if a future change reintroduces the bug:

| Path | Test | What it stresses |
|---|---|---|
| Observer slice snapshot in `pipeline.notify` | `internal/pipeline/notify_race_test.go::TestNotify_ObserverRegistrationDuringDispatch` | Concurrent `AddObserver` calls during a flood of `ProcessIngressWithAuth` calls. POV-1 flagged the prior `observers := p.observers` aliasing read; the fix uses `copy()` into a fresh slice under RLock. |
| Per-identity rate limiter LRU map | `pkg/ratelimit/per_identity_test.go` (parallel sub-tests) | Many goroutines pulling tokens from the same bucket map with concurrent eviction. |
| EWMA tracker LRU map | `pkg/session/ewma_test.go` (parallel sub-tests) | Multiple subjects updating + reading + evicting under the shared mutex. |
| Quarantine JSONL store | `internal/quarantine/store_test.go` (`TestStore_ConcurrentWrites` — 512 concurrent writers) | File mutex + atomic-rename + JSONL append under contention. |
| Merkle audit tree append + replay | `internal/audit/merkle_test.go` (parallel append + read paths) | Sibling-hash promotion + root recomputation under concurrent appends. |
| Pipeline body truncation marker | `internal/pipeline/body_truncated_test.go` | Asserts the leaf carries `body_truncated:true` when the body exceeds the cap (R-B6). |
| Merkle signed-root export goroutine | `cmd/serve_refinements_test.go::TestRunMerkleSignedRootExport_RespectsContextCancel` | Drives the ticker goroutine until `ctx.Cancel()` and asserts it exits within 500 ms (R-B4 contract). |
| SVID verifier boot-time fail-closed | `cmd/serve_refinements_test.go::TestBuildSVIDVerifier_*` | Covers the four failure modes that prevent boot when `policy.reef.require_svid=true` (R-B3). |

## Reproducing locally

```bash
# Ubuntu / WSL2
sudo apt install -y build-essential gcc

# Mac
brew install gcc

# Then, from the lobstertrap-reef directory:
make test-race
```

The `make test-race` target uses `CGO_ENABLED=1`, so missing `gcc` surfaces
as a build error rather than silently passing without race instrumentation.

## CI guardrail

`make test-race` is the canonical post-refactor check before any commit
touching:

- `internal/pipeline/*.go` (observer pattern, action dispatch)
- `internal/quarantine/*.go` (file mutex paths)
- `pkg/ratelimit/*.go` / `pkg/session/*.go` (shared LRU maps)
- `internal/audit/*.go` (Merkle tree mutex paths)

A subsequent CI integration step will enforce this gate; for now the human
running the refinement re-runs it locally before pushing.
