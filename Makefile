BINARY := nsmcp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo 0.1.0-dev)
PRODUCT ?= platform
GOFLAGS := -mod=mod
LDFLAGS := -X main.version=$(VERSION)
MCPB_STAGE ?= dist/mcpb
MCPB_FILE ?= dist/nsmcp.mcpb
MCPB_MANIFEST := packaging/mcpb/manifest.json
MCPB_GOCACHE ?= /private/tmp/nsmcp-mcpb-gocache
MCPB_CHECKSUM := $(dir $(MCPB_FILE))mcpb-checksums.txt

.PHONY: build mcpb test vet fmt lint run clean

build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/nsmcp

# MCPB is a single cross-platform archive: a universal macOS binary plus a
# Windows amd64 binary selected through the manifest's platform override.
# lipo and ad-hoc codesigning make this target macOS-only.
mcpb:
	@command -v lipo >/dev/null
	@command -v codesign >/dev/null
	@command -v zip >/dev/null
	rm -rf $(MCPB_STAGE) $(MCPB_FILE) $(MCPB_CHECKSUM)
	mkdir -p $(MCPB_STAGE)/server $(dir $(MCPB_FILE))
	sed 's/"version": "[^"]*"/"version": "$(VERSION)"/' $(MCPB_MANIFEST) > $(MCPB_STAGE)/manifest.json
	cp LICENSE.md $(MCPB_STAGE)/LICENSE.md
	GOCACHE=$(MCPB_GOCACHE) CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -trimpath -ldflags "-s -w $(LDFLAGS)" -o $(MCPB_STAGE)/server/nsmcp-arm64 ./cmd/nsmcp
	GOCACHE=$(MCPB_GOCACHE) CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -trimpath -ldflags "-s -w $(LDFLAGS)" -o $(MCPB_STAGE)/server/nsmcp-amd64 ./cmd/nsmcp
	lipo -create -output $(MCPB_STAGE)/server/nsmcp $(MCPB_STAGE)/server/nsmcp-arm64 $(MCPB_STAGE)/server/nsmcp-amd64
	rm $(MCPB_STAGE)/server/nsmcp-arm64 $(MCPB_STAGE)/server/nsmcp-amd64
	chmod 0755 $(MCPB_STAGE)/server/nsmcp
	codesign --force --sign - $(MCPB_STAGE)/server/nsmcp
	GOCACHE=$(MCPB_GOCACHE) CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -trimpath -ldflags "-s -w $(LDFLAGS)" -o $(MCPB_STAGE)/server/nsmcp.exe ./cmd/nsmcp
	cd $(MCPB_STAGE) && zip -q -X -r $(abspath $(MCPB_FILE)) manifest.json LICENSE.md server
	cd $(dir $(MCPB_FILE)) && shasum -a 256 $(notdir $(MCPB_FILE)) > $(notdir $(MCPB_CHECKSUM))
	@echo "built $(MCPB_FILE)"

test:
	go test $(GOFLAGS) ./...

vet:
	go vet $(GOFLAGS) ./...

fmt:
	gofmt -w .

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run ./...

run: build
	./$(BINARY) serve --product $(PRODUCT)

clean:
	rm -f $(BINARY)
