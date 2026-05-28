.PHONY: build run docker-build docker-up docker-down test clean lint

BINARY  = skyguard
VERSION ?= 1.0.0

build:
	CGO_ENABLED=0 go build \
	  -ldflags="-w -s -X main.Version=$(VERSION)" \
	  -o bin/$(BINARY) ./cmd/skyguard

run:
	go run ./cmd/skyguard -config configs/skyguard.example.yaml

docker-build:
	docker build -t skyguard:$(VERSION) -t skyguard:latest .

docker-up:
	docker compose up -d

docker-down:
	docker compose down

test:
	go test ./...

clean:
	rm -rf bin/
	go clean

lint:
	golangci-lint run

.DEFAULT_GOAL := build