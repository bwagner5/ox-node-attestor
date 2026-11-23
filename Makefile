# Snapshot tags are skipped.
VERSION ?= $(shell git describe --tags --always --exclude '*-*' | sed -e 's/^v//')

MY_IMAGE_REPO ?= ghcr.io/$(GITHUB_USER)/oxide-node-attestor
IMAGE_REPO ?= ghcr.io/oxidecomputer/oxide-node-attestor
HELM_OCI_REPO ?= ghcr.io/oxidecomputer/helm-charts
CHART_NAME ?= oxide-node-attestor
CHART_DIR ?= charts/$(CHART_NAME)
IMAGE_TAG ?= dev
KO_DOCKER_REPO ?= $(IMAGE_REPO)
KOCACHE ?= ~/.ko
MAKEFILE_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
TOOLS_MOD := $(MAKEFILE_PATH)/tools/go.mod
GO_TOOL := go tool -modfile=$(TOOLS_MOD)
NAMESPACE ?= kube-system
SHELLCHECK_VERSION ?= v0.11.0

LDFLAGS ?= -ldflags=-X=github.com/oxidecomputer/oxide-node-attestor/pkg/version.Version=$(VERSION)
GOFLAGS += $(LDFLAGS)
WITH_GOFLAGS = GOFLAGS="$(GOFLAGS)"

GOARCH ?= $(shell go env GOARCH)

SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

SHELL_SOURCES = $(shell git ls-files --cached --others --exclude-standard '*.sh')

.PHONY: all
all: precommit

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: generate
generate: ## Refresh chart docs
	$(HELM_DOCS) --chart-search-root charts

.PHONY: verify
verify: release-check lint-shell ## Run linters and vetting on codebase with no commit checks and no mutations.
	$(GOLANGCI_LINT) config verify
	$(GOLANGCI_LINT) run
	go vet ./...

.PHONY: lint-shell
lint-shell: shellcheck ## Run shellcheck over the checked-in shell scripts.
	$(SHELLCHECK) --severity=style $(SHELL_SOURCES)

.PHONY: fix
fix: ## Perform lint, fmt, and mod/sum file fixes
	go mod tidy
	go fmt ./...
	cd tools/ && go mod tidy
	$(GOLANGCI_LINT) run --fix

.PHONY: test
test: generate ## Run tests.
	go test -v ./... -coverprofile cover.out

.PHONY: coverage
coverage: ## Render the coverage profile written by `make test` as HTML
	go tool cover -html cover.out -o coverage.html

.PHONY: vulncheck
vulncheck: ## Verify code vulnerabilities
	$(GOVULNCHECK) ./pkg/...

.PHONY: licenses
licenses: ## Verifies dependency licenses
	! $(GO_LICENSES) csv ./... | grep -v -e 'MIT' -e 'Apache-2.0' -e 'BSD-3-Clause' -e 'BSD-2-Clause' -e 'ISC' -e 'MPL-2.0'

.PHONY: precommit
precommit: fix verify test release-dry-run ## Run all precommit checks (lint, fix, fmt, tests, release dry run).

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

export PATH := $(LOCALBIN):$(PATH)

## Tool Binaries
KO ?= KOCACHE=$(KOCACHE) $(GO_TOOL) ko
GORELEASER ?= $(GO_TOOL) goreleaser
SHELLCHECK ?= $(LOCALBIN)/shellcheck
GOVULNCHECK ?= $(GO_TOOL) govulncheck
GO_LICENSES ?= $(GO_TOOL) go-licenses
GOLANGCI_LINT ?= $(GO_TOOL) golangci-lint
HELM ?= $(GO_TOOL) helm
HELM_DOCS ?= $(GO_TOOL) helm-docs

.PHONY: tools
tools: shellcheck $(LOCALBIN) ## Install all required dev tools to the repo's local bin/
	GOBIN="$(LOCALBIN)" go install -modfile=$(TOOLS_MOD) tool

.PHONY: shellcheck
shellcheck: $(LOCALBIN)
	@command -v $(SHELLCHECK) >/dev/null 2>&1 && exit 0; \
		curl -fsSL "https://github.com/koalaman/shellcheck/releases/download/$(SHELLCHECK_VERSION)/shellcheck-$(SHELLCHECK_VERSION).$$(uname -s | tr '[:upper:]' '[:lower:]').$$(uname -m | sed 's/arm64/aarch64/').tar.gz" \
		| tar -xzf - -C "$(LOCALBIN)" --strip-components=1 "shellcheck-$(SHELLCHECK_VERSION)/shellcheck"

IMAGE_REF_FILE := $(shell echo "$${TMPDIR:-/tmp}")/oxide-node-attestor-image-ref

.PHONY: build
build: ## Builds a container image using ko and pushes to $KO_DOCKER_REPO
	$(WITH_GOFLAGS) KO_DOCKER_REPO="$(KO_DOCKER_REPO)" $(KO) build --bare ./cmd/oxide-node-attestor | tee $(IMAGE_REF_FILE)

.PHONY: build-dev
build-dev: ## Builds a container image using ko and pushes to $MY_IMAGE_REPO
	$(WITH_GOFLAGS) KO_DOCKER_REPO="$(MY_IMAGE_REPO)" $(KO) build --bare ./cmd/oxide-node-attestor | tee $(IMAGE_REF_FILE)

.PHONY: binary
binary: ## Build the attestor and the node's oxide-node-join (linux) using go build
	go build $(GOFLAGS) -o oxide-node-attestor-$(GOARCH) ./cmd/oxide-node-attestor
	GOOS=linux go build $(GOFLAGS) -o oxide-node-join-linux-$(GOARCH) ./cmd/oxide-node-join

ARTIFACTS ?= $(PWD)/_artifacts

.PHONY: manifests
manifests: generate
	rm -rf $(ARTIFACTS)/helm
	mkdir -p $(ARTIFACTS)/helm
	$(HELM) package $(CHART_DIR) \
		--version $(VERSION) \
		--app-version $(VERSION) \
		--destination $(ARTIFACTS)/helm
	test -f $(ARTIFACTS)/helm/$(CHART_NAME)-$(VERSION).tgz

##@ Dev Deployment

## Extra helm options for the dev deployment targets
HELM_OPTS ?= --set settings.oxide.host=${OXIDE_HOST} \
			--set settings.oxide.project=${OXIDE_PROJECT} \
			--create-namespace

.PHONY: deploy
deploy: ## Deploy the attestor to the cluster in ~/.kube/config. Pulls a remote image, but uses the local helm chart.
	$(HELM) upgrade --install oxide-node-attestor $(CHART_DIR) \
		--namespace $(NAMESPACE) \
		$(HELM_OPTS) \
		--set image.repository=$(IMAGE_REPO) \
		--set image.tag=$(IMAGE_TAG) \
		--wait

.PHONY: helm-apply
helm-apply:
	REF="$$(cat $(IMAGE_REF_FILE))"; \
	$(HELM) upgrade --install oxide-node-attestor $(CHART_DIR) \
		--namespace $(NAMESPACE) \
		$(HELM_OPTS) \
		--set image.repository="$${REF%:*}" \
		--set image.tag="$${REF##*:}" \
		--wait

.PHONY: apply
apply: build-dev helm-apply ## Build/push the image with ko and deploy that exact digest to the current kube context.

.PHONY: undeploy
undeploy: ## Undeploy the attestor from the K8s cluster specified in ~/.kube/config.
	$(HELM) uninstall oxide-node-attestor --namespace $(NAMESPACE) --wait

##@ CI and Release

.PHONY: ci-verify
ci-verify: precommit ## Verify fmt, linters, mod/sum files, chart docs, etc. and fail if any mutate.
	@git diff --exit-code || { \
		echo; \
		echo "ERROR: working tree is dirty after 'make ci-verify'."; \
		echo "Run 'make fix generate' locally and commit the result."; \
		exit 1; \
	}

.PHONY: release-check
release-check: tools
	$(GORELEASER) check

.PHONY: release-dry-run
release-dry-run: tools ## Build the release artifacts locally without publishing.
	$(GORELEASER) release --snapshot --clean

.PHONY: snapshot-tag
snapshot-tag: ## Tag HEAD as a snapshot prerelease and print the push command (see hack/snapshot-tag.sh). PR= and REMOTE= override detection.
	@hack/snapshot-tag.sh $(if $(PR),--pr $(PR)) $(if $(REMOTE),--remote $(REMOTE))

# GORELEASER_CURRENT_TAG disambiguates a commit carrying both a snapshot and a
# stable tag. The previous tag skips snapshots so changelogs diff against the
# last stable release.
.PHONY: release
release: tools ## Build and push the multi-arch (linux/amd64,linux/arm64) images to ghcr, push the helm chart, and cut a GitHub release.
	set -e; \
	tag="$${GORELEASER_CURRENT_TAG:-}"; \
	[[ -n "$$tag" ]] || tag="$$(git describe --tags --exact-match)"; \
	prev="$$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' --exclude '*-*' "$$tag^" 2>/dev/null || true)"; \
	GORELEASER_CURRENT_TAG="$$tag" GORELEASER_PREVIOUS_TAG="$$prev" $(GORELEASER) release --clean
	for chart in $(ARTIFACTS)/helm/*.tgz; do \
		$(HELM) push "$$chart" "oci://$(HELM_OCI_REPO)" --debug; \
	done
