.PHONY: build run check-config config docker-build docker-up docker-down test race vet clean lint

BINARY  = skyguard
# A release tag on this commit gives the version; otherwise "dev".
VERSION ?= $(or $(shell git describe --tags --exact-match 2>/dev/null | sed 's/^v//'),dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  = -w -s -X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildDate=$(DATE)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/skyguard

run:
	go run ./cmd/skyguard -config configs/skyguard.example.yaml

check-config:
	go run ./cmd/skyguard -check-config -config configs/skyguard.yaml

# Create the config docker-compose.yml mounts (never overwrites an existing one).
config:
	@test -f configs/skyguard.yaml || cp configs/skyguard.example.yaml configs/skyguard.yaml
	@chmod 600 configs/skyguard.yaml
	@echo "edit configs/skyguard.yaml (whitelist + dashboard password), then: make docker-up"

docker-build:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t skyguard:$(VERSION) -t skyguard:latest .

docker-up: config
	docker compose up -d --build

docker-down:
	docker compose down

test:
	go test ./...

race:
	CGO_ENABLED=1 go test -race ./...

vet:
	go vet ./...

clean:
	rm -rf bin/
	go clean

lint:
	golangci-lint run

.DEFAULT_GOAL := build
