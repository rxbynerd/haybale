default: build test

build:
    go build -o haybale ./cmd/haybale

test:
    go test ./...

# Race-detector pass over the full module. haybale is small enough
# (single module, no goroutine-heavy subsystems yet beyond the proxy and
# e2e harness) that sweeping ./... under -race is cheap — unlike
# Stirrup's targeted package list, there's no need to scope this down.
test-race:
    go test -race ./...

lint:
    golangci-lint run ./...

clean:
    rm -f haybale
