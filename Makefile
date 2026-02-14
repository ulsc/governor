BINARY := governor
BIN_DIR := bin
INSTALL_DIR ?= $(HOME)/.local/bin
GO ?= go
GOFLAGS ?= -mod=readonly
IMAGE ?= governor-runner:local
CODEX_NPM_VERSION ?= 0.101.0
CODEX_NPM_INTEGRITY ?= sha512-H874q5K5I3chrT588BaddMr7GNvRYypc8C1MKWytNUF2PgxWMko2g/2DgKbt5OdajZKMsWdbsPywu34KQGf5Qw==
VERSION ?= dev
LDFLAGS := -ldflags "-X governor/internal/version.Version=$(VERSION)"

INPUT ?= .
ARGS ?=

.PHONY: build test run install clean build-isolation-image

build:
	mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BIN_DIR)/$(BINARY) .

test:
	$(GO) test $(GOFLAGS) ./...

run:
	$(GO) run $(GOFLAGS) . audit "$(INPUT)" $(ARGS)

install: build
	mkdir -p $(INSTALL_DIR)
	cp $(BIN_DIR)/$(BINARY) $(INSTALL_DIR)/$(BINARY)
	@echo "Installed $(BINARY) to $(INSTALL_DIR)/$(BINARY)"

build-isolation-image:
	docker build \
		--build-arg CODEX_NPM_VERSION=$(CODEX_NPM_VERSION) \
		--build-arg CODEX_NPM_INTEGRITY=$(CODEX_NPM_INTEGRITY) \
		-f Dockerfile.isolate-runner -t $(IMAGE) .

clean:
	rm -rf $(BIN_DIR)
