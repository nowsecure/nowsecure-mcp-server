BINARY := nsmcp
VERSION ?= 0.1.0
GOFLAGS := -mod=mod
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet fmt lint run clean

build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/nsmcp

test:
	go test $(GOFLAGS) ./...

vet:
	go vet $(GOFLAGS) ./...

fmt:
	gofmt -w .

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run ./...

run: build
	./$(BINARY) serve

clean:
	rm -f $(BINARY)
