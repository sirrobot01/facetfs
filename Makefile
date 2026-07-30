.PHONY: all build check fmt test race vet clean

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

clean:
	rm -f coverage.out coverage.html
