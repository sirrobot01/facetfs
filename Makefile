.PHONY: all build check fmt test race vet bench fuzz clean

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
	go test ./internal/xdr ./nfs4 -run '^$$' -bench . -benchmem

# Longer campaigns than CI runs. Set FUZZTIME to change the budget per target.
fuzz:
	go test ./internal/xdr -run '^$$' -fuzz FuzzDecoder -fuzztime $(FUZZTIME)
	go test ./nfs4 -run '^$$' -fuzz FuzzServeConn -fuzztime $(FUZZTIME)
	go test ./nfs4 -run '^$$' -fuzz FuzzParseUniversalAddr -fuzztime $(FUZZTIME)

clean:
	rm -f coverage.out coverage.html
