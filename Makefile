VERSION ?= 0.1.0-dev

.PHONY: build test clean

build: dist/sentineld

dist/sentineld: $(shell find daemon -name '*.go') daemon/go.mod
	mkdir -p dist
	cd daemon && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o ../dist/sentineld ./cmd/sentineld

test:
	cd daemon && go vet ./... && go test ./...
	prove -Iperl/lib perl/t/

clean:
	rm -rf dist
