# Makefile for oidc-demo
# Run "make" or "make help" to see all targets.

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------
BINARY      := oidc-demo
BIN_DIR     := bin
CMD_PKG     := ./cmd
MAIN_PKG    := .
COVERAGE    := coverage.out

# Get git info, but do not fail if this is not a git repo.
GIT_COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
GIT_DIRTY   := $(shell git status --porcelain 2>/dev/null | head -n 1)
BUILD_DATE  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

ifeq ($(GIT_DIRTY),)
VERSION     := $(GIT_COMMIT)
else
VERSION     := $(GIT_COMMIT)-dirty
endif

# -s -w  : strip the symbol table and debug info to make the binary smaller
# -trimpath: remove local file system paths from the binary
LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(GIT_COMMIT) \
	-X main.date=$(BUILD_DATE)

GO_BUILD_FLAGS := -trimpath -ldflags "$(LDFLAGS)"

.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
.PHONY: help
help: ## Show this help
	@echo "oidc-demo - available make targets:"
	@echo ""
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ---------------------------------------------------------------------------
# Required targets
# ---------------------------------------------------------------------------
.PHONY: fmt
fmt: ## Format all Go source code
	go fmt ./...

.PHONY: vet
vet: ## Run go vet to find suspicious code
	go vet ./...

.PHONY: test
test: ## Run all tests
	go test ./...

.PHONY: build
build: ## Build the binary into ./bin
	@mkdir -p $(BIN_DIR)
	go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(BINARY) $(MAIN_PKG)
	@echo "built $(BIN_DIR)/$(BINARY) ($(VERSION))"

# ---------------------------------------------------------------------------
# Extra useful targets
# ---------------------------------------------------------------------------
.PHONY: test-verbose
test-verbose: ## Run all tests with extra output
	go test -v ./...

.PHONY: test-race
test-race: ## Run all tests with the race detector
	go test -race ./...

.PHONY: cover
cover: ## Run tests and write coverage report to coverage.out
	go test -coverprofile=$(COVERAGE) ./...
	go tool cover -func=$(COVERAGE)

.PHONY: cover-html
cover-html: cover ## Open coverage report in a browser
	go tool cover -html=$(COVERAGE)

.PHONY: check
check: fmt vet test ## Run fmt, vet and test together

.PHONY: tidy
tidy: ## Tidy up go.mod and go.sum
	go mod tidy

.PHONY: verify
verify: ## Check that go.mod and go.sum are clean (use in CI)
	go mod tidy
	go mod verify

.PHONY: clean
clean: ## Remove build output and coverage files
	rm -rf $(BIN_DIR) $(COVERAGE)

.PHONY: install
install: ## Install the binary into GOPATH/bin
	go install $(GO_BUILD_FLAGS) $(MAIN_PKG)

.PHONY: run
run: build ## Build then show the help
	@$(BIN_DIR)/$(BINARY) --help

.PHONY: serve
serve: build ## Build then start the mock IdP on port 8085
	@$(BIN_DIR)/$(BINARY) serve --port 8085
