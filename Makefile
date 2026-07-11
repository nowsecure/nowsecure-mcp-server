BINARY := nsmcp
VERSION ?= 0.1.0
GOFLAGS := -mod=mod
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet fmt run clean

build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/nsmcp

test:
	go test $(GOFLAGS) ./...

vet:
	go vet $(GOFLAGS) ./...

fmt:
	gofmt -w .

run: build
	./$(BINARY) serve

clean:
	rm -f $(BINARY)
