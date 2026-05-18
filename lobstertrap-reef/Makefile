.PHONY: build build-static test test-race vet bench clean install

BINARY := lobstertrap
VERSION := 0.1.0
LDFLAGS := -ldflags="-s -w -X github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/cmd.Version=$(VERSION)"

build:
	go build -o $(BINARY) .

build-static:
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY) .

test:
	go test ./... -v

# Refinement R-B7 (Phase B Round 1 Batch B): run the full race detector
# across every package. Requires gcc (install via `apt install build-essential`
# on Debian/Ubuntu / `brew install gcc` on macOS). Output is tee'd into
# race-test.log; RACE_TEST.md captures the canonical green run.
test-race:
	CGO_ENABLED=1 go test -race -count=1 ./... 2>&1 | tee race-test.log

vet:
	go vet ./...

bench:
	go test ./internal/inspector/ -bench=. -benchmem

clean:
	rm -f $(BINARY) $(BINARY).exe

install:
	go install $(LDFLAGS) .

# Cross-compilation
build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 .

build-windows:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY).exe .

build-darwin:
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-darwin-arm64 .

build-all: build-linux build-windows build-darwin
