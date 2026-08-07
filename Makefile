# Copyright Jetstack Ltd. See LICENSE for details.
BINDIR    ?= $(CURDIR)/bin
HACK_DIR  ?= hack
PATH      := $(BINDIR):$(PATH)
ARTIFACTS ?= artifacts
ARCH      ?= amd64

SHELL = /bin/bash -o pipefail

export GO111MODULE=on

help:  ## display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: help build docker_build test depend verify all clean generate e2e e2e-clean

UNAME_S := $(shell uname -s)
GOLANGCILINT_VERSION := 1.21.0
# kubectl version used only as a download fallback when no system kubectl is on
# PATH (the e2e suite prefers the host's kubectl, see the $(BINDIR)/kubectl rule).
KUBECTL_VERSION ?= v1.31.4
KUBECTL_OS   := $(shell go env GOOS)
KUBECTL_ARCH := $(shell go env GOARCH)
ifeq ($(UNAME_S),Linux)
	SHASUM := sha256sum -c
	GOLANGCILINT_URL := https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCILINT_VERSION)/golangci-lint-$(GOLANGCILINT_VERSION)-linux-amd64.tar.gz
	GOLANGCILINT_HASH := 2c861f8dc56b560474aa27cab0c075991628cc01af3451e27ac82f5d10d5106b
endif
ifeq ($(UNAME_S),Darwin)
	SHASUM := shasum -a 256 -c
	GOLANGCILINT_URL := https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCILINT_VERSION)/golangci-lint-$(GOLANGCILINT_VERSION)-darwin-amd64.tar.gz
	GOLANGCILINT_HASH := 2b2713ec5007e67883aa501eebb81f22abfab0cf0909134ba90f60a066db3760
endif

$(BINDIR)/mockgen:
	mkdir -p $(BINDIR)
	go build -o $(BINDIR)/mockgen go.uber.org/mock/mockgen

# Provide a modern kubectl for the e2e helper. Prefer the host's kubectl (kept
# current by the developer / CI runner); fall back to a versioned download. The
# ancient pinned v1.18.0 that used to live here could not exec against modern
# API servers.
$(BINDIR)/kubectl:
	mkdir -p $(BINDIR)
	@if command -v kubectl >/dev/null 2>&1; then \
		echo "kubectl: linking system kubectl $$(command -v kubectl)"; \
		ln -sf "$$(command -v kubectl)" $(BINDIR)/kubectl; \
	else \
		echo "kubectl: downloading $(KUBECTL_VERSION) for $(KUBECTL_OS)/$(KUBECTL_ARCH)"; \
		curl --fail -sL -o $(BINDIR)/kubectl "https://dl.k8s.io/release/$(KUBECTL_VERSION)/bin/$(KUBECTL_OS)/$(KUBECTL_ARCH)/kubectl"; \
		chmod +x $(BINDIR)/kubectl; \
	fi

.PHONY: $(BINDIR)/golangci-lint
$(BINDIR)/golangci-lint: $(BINDIR)/golangci-lint-$(GOLANGCILINT_VERSION)
	@ln -fs golangci-lint-$(GOLANGCILINT_VERSION) $(BINDIR)/golangci-lint

$(BINDIR)/golangci-lint-$(GOLANGCILINT_VERSION):
	mkdir -p $(BINDIR) $(BINDIR)/.golangci-lint
	curl --fail -sL -o $(BINDIR)/.golangci-lint.tar.gz $(GOLANGCILINT_URL)
	echo "$(GOLANGCILINT_HASH)  $(BINDIR)/.golangci-lint.tar.gz" | $(SHASUM)
	tar xvf $(BINDIR)/.golangci-lint.tar.gz -C $(BINDIR)/.golangci-lint
	mv $(BINDIR)/.golangci-lint/*/golangci-lint $(BINDIR)/golangci-lint-$(GOLANGCILINT_VERSION)
	rm -rf $(BINDIR)/.golangci-lint $(BINDIR)/.golangci-lint.tar.gz

depend: $(BINDIR)/mockgen $(BINDIR)/kubectl $(BINDIR)/golangci-lint

verify_boilerplate:
	$(HACK_DIR)/verify-boilerplate.sh

go_fmt:
	@set -e; \
	GO_FMT=$$(git ls-files *.go | xargs gofmt -d); \
	if [ -n "$${GO_FMT}" ] ; then \
		echo "Please run go fmt"; \
		echo "$$GO_FMT"; \
		exit 1; \
	fi

go_vet:
	go vet ./cmd

go_lint: $(BINDIR)/golangci-lint ## lint golang code for problems
	$(BINDIR)/golangci-lint run --timeout 3m

clean: ## clean up created files
	rm -rf \
		$(BINDIR) \
		$(CURDIR)/pkg/mocks/authenticator.go \
		$(CURDIR)/test/e2e/framework/issuer/bin \
		$(CURDIR)/test/e2e/framework/fake-apiserver/bin

verify: depend verify_boilerplate go_fmt go_vet go_lint ## verify code and mod

generate: depend ## generates mocks and assets files
	go generate $$(go list ./pkg/... ./cmd/...)

test: generate verify ## run all go tests
	mkdir -p $(ARTIFACTS)
	go test -v -bench $$(go list ./pkg/... ./cmd/... | grep -v pkg/e2e) | tee $(ARTIFACTS)/go-test.stdout
	cat $(ARTIFACTS)/go-test.stdout | go run github.com/jstemmer/go-junit-report > $(ARTIFACTS)/junit-go-test.xml

# Name of the kind cluster the e2e suite creates (must match the const in
# test/kind/kind.go). Used by e2e-clean for the failure/interrupt safety net.
E2E_CLUSTER_NAME := kube-oidc-proxy-e2e
E2E_TIMEOUT      ?= 30m

# Prerequisites (local runs): go, docker (daemon running), kind, and kubectl on
# PATH. The suite builds and side-loads the proxy + test-tool images itself and
# creates/destroys its own kind cluster, so no pre-existing cluster is needed.
e2e: $(BINDIR)/kubectl ## run the e2e suite hermetically (creates + destroys its own kind cluster)
	mkdir -p $(ARTIFACTS)
	@echo "e2e: removing any stale cluster from a previous run"
	@$(MAKE) --no-print-directory e2e-clean
	trap '$(MAKE) --no-print-directory e2e-clean' EXIT; \
	KUBE_OIDC_PROXY_ROOT_PATH="$$(pwd)" go test -timeout $(E2E_TIMEOUT) -v --count=1 ./test/e2e/suite/. 2>&1 | tee $(ARTIFACTS)/e2e.log

e2e-clean: ## delete the e2e kind cluster if present (safe to run anytime)
	@kind delete cluster --name $(E2E_CLUSTER_NAME) >/dev/null 2>&1 || true

build: generate ## build kube-oidc-proxy
	mkdir -p ./bin/amd64
	mkdir -p ./bin/arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-w $(shell hack/version-ldflags.sh)' -o ./bin/amd64/kube-oidc-proxy ./cmd/.
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '-w $(shell hack/version-ldflags.sh)' -o ./bin/arm64/kube-oidc-proxy ./cmd/.

docker_build: generate test build ## build docker image
	GOARCH=$(ARCH) GOOS=linux CGO_ENABLED=0 go build -ldflags '-w $(shell hack/version-ldflags.sh)' -o ./bin/kube-oidc-proxy  ./cmd/.
	docker build -t kube-oidc-proxy .

all: test build ## runs tests, build

image: all docker_build ## runs tests, build and docker build

dev_cluster_create: depend ## create dev cluster for development testing
	KUBE_OIDC_PROXY_ROOT_PATH="$$(pwd)" go run -v ./test/environment/dev create

dev_cluster_deploy: depend ## deploy into dev cluster
	KUBE_OIDC_PROXY_ROOT_PATH="$$(pwd)" go run -v ./test/environment/dev deploy

dev_cluster_destroy: depend ## destroy dev cluster
	KUBE_OIDC_PROXY_ROOT_PATH="$$(pwd)" go run -v ./test/environment/dev destroy
