.PHONY: all build check fmt test race vet clean

all: check build

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/facetfsd ./cmd/facetfsd

check: fmt vet test

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -d . && exit 1)

vet:
	go vet ./...

test:
	CGO_ENABLED=0 go test ./...

race:
	go test -race ./...

clean:
	rm -f bin/facetfsd coverage.out coverage.html
