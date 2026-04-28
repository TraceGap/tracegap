GO ?= go
BINARY ?= tgap
OUT_DIR ?= dist
CGO_ENABLED ?= 0

PKG := ./cmd/tgap
LDFLAGS := -s -w

.PHONY: test benchmark lint build build-local clean cross-build darwin-amd64 darwin-arm64 linux-amd64 linux-arm64 windows-amd64

test:
	$(GO) test ./...

benchmark:
	$(GO) test ./internal/analyzer -bench=. -benchmem

lint:
	$(GO) vet ./...

build: build-local

build-local:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BINARY) $(PKG)

cross-build: darwin-amd64 darwin-arm64 linux-amd64 linux-arm64 windows-amd64

darwin-amd64:
	mkdir -p $(OUT_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BINARY)-darwin-amd64 $(PKG)

darwin-arm64:
	mkdir -p $(OUT_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BINARY)-darwin-arm64 $(PKG)

linux-amd64:
	mkdir -p $(OUT_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BINARY)-linux-amd64 $(PKG)

linux-arm64:
	mkdir -p $(OUT_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BINARY)-linux-arm64 $(PKG)

windows-amd64:
	mkdir -p $(OUT_DIR)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=windows GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(OUT_DIR)/$(BINARY)-windows-amd64.exe $(PKG)

clean:
	rm -rf $(OUT_DIR)
