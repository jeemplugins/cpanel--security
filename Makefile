VERSION ?= 0.1.1-dev
# cPanel mounts /tmp noexec, so go test cannot run binaries from there.
export GOTMPDIR ?= $(CURDIR)/.gotmp

.PHONY: build test clean

build: dist/sentineld

dist/sentineld: $(shell find daemon -name '*.go') daemon/go.mod
	mkdir -p dist $(GOTMPDIR)
	cd daemon && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o ../dist/sentineld ./cmd/sentineld

test:
	mkdir -p $(GOTMPDIR)
	cd daemon && go vet ./... && go test ./...
	prove -Iperl/lib perl/t/

clean:
	rm -rf dist .gotmp
