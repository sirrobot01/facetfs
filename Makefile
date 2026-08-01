.PHONY: all build check fmt test race vet bench bench-protocols fuzz clean

FUZZTIME ?= 5m

all: check

build:
	CGO_ENABLED=0 go build ./...

check: fmt vet test

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -d . && exit 1)

vet:
	go vet ./...

test:
	CGO_ENABLED=0 go test ./...

race:
	go test -race ./...

bench:
	go test ./internal/xdr ./nfs4 ./smb ./facetcache -run '^$$' -bench . -benchmem

# Compare warm, end-to-end protocol operations over loopback and MemFS.
bench-protocols:
	go test ./nfs4 -run '^$$' -bench '^BenchmarkProtocolComparison$$' -benchmem

# Longer campaigns than CI runs. Set FUZZTIME to change the budget per target.
fuzz:
	go test ./internal/xdr -run '^$$' -fuzz FuzzDecoder -fuzztime $(FUZZTIME)
	go test ./nfs4 -run '^$$' -fuzz FuzzServeConn -fuzztime $(FUZZTIME)
	go test ./nfs4 -run '^$$' -fuzz FuzzParseUniversalAddr -fuzztime $(FUZZTIME)
	go test ./nfs4 -run '^$$' -fuzz FuzzCallbackReply -fuzztime $(FUZZTIME)
	go test ./smb -run '^$$' -fuzz FuzzHandleFrame -fuzztime $(FUZZTIME)
	go test ./smb -run '^$$' -fuzz FuzzReadFrame -fuzztime $(FUZZTIME)
	go test ./smb -run '^$$' -fuzz FuzzNegotiate -fuzztime $(FUZZTIME)
	go test ./smb -run '^$$' -fuzz FuzzNTLMAndPaths -fuzztime $(FUZZTIME)

clean:
	rm -f coverage.out coverage.html
