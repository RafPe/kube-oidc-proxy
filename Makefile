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

.PHONY: help build docker_build test depend verify all clean generate e2e e2e-clean verify-e2e-shards

# golangci-lint is installed via the upstream, GOOS/GOARCH-aware installer,
# pinned to a supported v2 release. Keep this in lockstep with the version the
# CI lint job pins (see .github/workflows/test.yaml) so local and CI agree.
GOLANGCILINT_VERSION := v2.12.2
# kubectl version used only as a download fallback when no system kubectl is on
# PATH (the e2e suite prefers the host's kubectl, see the $(BINDIR)/kubectl rule).
KUBECTL_VERSION ?= v1.37.0
KUBECTL_OS   := $(shell go env GOOS)
KUBECTL_ARCH := $(shell go env GOARCH)

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

# Install golangci-lint using the upstream installer, pinned to the release
# tag. The installer picks the correct GOOS/GOARCH artifact, replacing the old
# amd64-only, hardcoded-hash download.
$(BINDIR)/golangci-lint:
	mkdir -p $(BINDIR)
	curl --fail -sSfL \
		https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCILINT_VERSION)/install.sh \
		| sh -s -- -b $(BINDIR) $(GOLANGCILINT_VERSION)

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
	go vet ./...

go_lint: $(BINDIR)/golangci-lint ## lint golang code for problems
	$(BINDIR)/golangci-lint run --timeout 5m ./...

clean: ## clean up created files
	rm -rf \
		$(BINDIR) \
		$(CURDIR)/pkg/mocks/authenticator.go \
		$(CURDIR)/test/e2e/framework/issuer/bin \
		$(CURDIR)/test/e2e/framework/fake-apiserver/bin

# generate (not just depend) so pkg/mocks/authenticator.go exists before
# go_vet ./... and go_lint compile the packages that reference it.
verify: generate verify_boilerplate go_fmt go_vet go_lint ## verify code and mod

generate: depend ## generates mocks and assets files
	go generate $$(go list ./pkg/... ./cmd/...)

test: generate verify ## run all go tests
	mkdir -p $(ARTIFACTS)
	go test -v -bench $$(go list ./pkg/... ./cmd/... ./test/tools/... ./test/e2e/versions/... | grep -v pkg/e2e) | tee $(ARTIFACTS)/go-test.stdout

# Name of the kind cluster the e2e suite creates (must match the const in
# test/kind/kind.go). Used by e2e-clean for the failure/interrupt safety net.
E2E_CLUSTER_NAME := kube-oidc-proxy-e2e
E2E_TIMEOUT      ?= 30m

# Optional Ginkgo label filter, forwarded to the suite binary as
# --ginkgo.label-filter. CI uses it to split the suite across a matrix of
# shards (`make e2e GINKGO_LABEL_FILTER=shard-a`, see .github/workflows/e2e.yaml).
# Empty (the default) runs every case.
GINKGO_LABEL_FILTER ?=
ifneq ($(strip $(GINKGO_LABEL_FILTER)),)
# -args passes everything after it to the test binary, so it must come last.
E2E_GOTEST_ARGS := -args --ginkgo.label-filter='$(GINKGO_LABEL_FILTER)'
endif

# Prerequisites (local runs): go, docker (daemon running), kind, and kubectl on
# PATH. The suite builds and side-loads the proxy + test-tool images itself and
# creates/destroys its own kind cluster, so no pre-existing cluster is needed.
e2e: $(BINDIR)/kubectl ## run the e2e suite hermetically (creates + destroys its own kind cluster)
	mkdir -p $(ARTIFACTS)
	@echo "e2e: removing any stale cluster from a previous run"
	@$(MAKE) --no-print-directory e2e-clean
	trap '$(MAKE) --no-print-directory e2e-clean' EXIT INT TERM; \
	KUBE_OIDC_PROXY_ROOT_PATH="$$(pwd)" go test -timeout $(E2E_TIMEOUT) -v --count=1 ./test/e2e/suite/. $(E2E_GOTEST_ARGS) 2>&1 | tee $(ARTIFACTS)/e2e.log

e2e-clean: ## delete the e2e kind cluster if present (safe to run anytime)
	@command -v kind >/dev/null 2>&1 || { \
		echo "e2e-clean: 'kind' not found on PATH; install kind to create or clean the e2e cluster." >&2; \
		echo "Without it a leftover cluster cannot be removed and 'e2e' would fail with 'node(s) already exist'." >&2; \
		exit 1; \
	}
	@kind delete cluster --name $(E2E_CLUSTER_NAME) >/dev/null 2>&1 || true

verify-e2e-shards: ## check every e2e case container carries exactly one shard label
	./hack/verify-e2e-shards.sh

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
