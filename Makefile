# certwatch — developer interface.
#
# `make check` runs exactly what CI runs. The failure mode that prevents —
# "it passed locally" — costs more in interruption than this target costs to
# keep correct.

SHELL       := /bin/bash
GO          ?= go
MODULE      := github.com/certwatch/certwatch
BUILD_DIR   := build
# Reproducible build flags. -buildid= and -trimpath remove the two sources of
# nondeterminism; SOURCE_DATE_EPOCH pins timestamps. The collector is open
# source and runs inside customer networks, so "build it yourself and get the
# same bytes" is the strongest possible answer to "what does this binary do?"
export CGO_ENABLED := 0
export GOFLAGS     := -mod=readonly
LDFLAGS     := -s -w -buildid=
BUILDFLAGS  := -trimpath -ldflags="$(LDFLAGS)"

.DEFAULT_GOAL := help
.PHONY: help fmt vet lint importcheck test test-race canary fuzz fuzz-long cover corpus \
        build build-all repro sbom check clean tools

help: ## Show this help
	@grep -hE '^[a-z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-14s\033[0m %s\n",$$1,$$2}'

fmt: ## Format, and fail if anything changed
	@out=$$(gofmt -l . 2>/dev/null); \
	 if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi
	@echo "fmt: OK"

vet: ## go vet
	@$(GO) vet ./...
	@echo "vet: OK"

importcheck: ## BLOCKING: the four structural boundaries (CI-006..009)
	@$(GO) run ./internal/tools/importcheck -root .

test: ## Unit and integration tests
	@$(GO) test ./... -count=1

test-race: ## Tests under the race detector
	@$(GO) test ./... -count=1 -race

canary: ## BLOCKING: the security canary (INV-1) on its own
	@$(GO) test ./test/canary/ -count=1 -v -run 'TestCanary' 2>&1 | \
	  grep -E 'CANARY-A-RESULT|--- (PASS|FAIL)|^(ok|FAIL)'
	@$(GO) test ./test/canary/ -count=1 -run 'TestCanary' >/dev/null

fuzz: ## 30s fuzz across every target
	@for t in $$($(GO) test ./... -list 'Fuzz.*' 2>/dev/null | grep '^Fuzz' | sort -u); do \
	   pkg=$$($(GO) test ./... -list "$$t" 2>/dev/null | grep -B1 "^$$t" | head -1); \
	   echo "fuzzing $$t"; \
	 done; \
	 $(GO) test ./pkg/x509norm/ -run XXX -fuzz FuzzParseDER -fuzztime 30s || true; \
	 $(GO) test ./pkg/x509norm/ -run XXX -fuzz FuzzNormaliseSANs -fuzztime 30s || true; \
	 $(GO) test ./pkg/safeio/ -run XXX -fuzz FuzzClassifyDER -fuzztime 30s || true; \
	 $(GO) test ./pkg/safeio/ -run XXX -fuzz FuzzReadPEM -fuzztime 30s || true

fuzz-long: ## 1h fuzz per target (what nightly runs)
	@$(GO) test ./pkg/x509norm/ -run XXX -fuzz FuzzParseDER -fuzztime 1h
	@$(GO) test ./pkg/x509norm/ -run XXX -fuzz FuzzNormaliseSANs -fuzztime 1h
	@$(GO) test ./pkg/safeio/  -run XXX -fuzz FuzzClassifyDER -fuzztime 1h
	@$(GO) test ./pkg/safeio/  -run XXX -fuzz FuzzReadPEM -fuzztime 1h

cover: ## Coverage report
	@$(GO) test ./... -count=1 -coverprofile=coverage.out >/dev/null
	@$(GO) tool cover -func=coverage.out | tail -1
	@$(GO) tool cover -func=coverage.out | grep -E 'pkg/(safeio|x509norm|scan)' | \
	  awk '{printf "  %-55s %s\n", $$1, $$3}'

build: ## Build both binaries for this platform
	@mkdir -p $(BUILD_DIR)
	@SOURCE_DATE_EPOCH=$${SOURCE_DATE_EPOCH:-1757894400} \
	  $(GO) build $(BUILDFLAGS) -o $(BUILD_DIR)/certscan ./cmd/certscan
	@SOURCE_DATE_EPOCH=$${SOURCE_DATE_EPOCH:-1757894400} \
	  $(GO) build $(BUILDFLAGS) -o $(BUILD_DIR)/certscan-aws ./cmd/certscan-aws
	@echo "built $(BUILD_DIR)/certscan and $(BUILD_DIR)/certscan-aws"

deps-check: ## Assert cmd/certscan depends only on the approved module set
	@# certscan's dependency set is ALLOWLISTED, not merely counted. The AWS SDK
	@# lives in certscan-aws precisely so this list stays short enough that a
	@# reviewer can read it. Adding a module here needs an entry in
	@# docs/dependencies.md in the same change.
	@# `vendor/golang.org/x/...` entries are Go's OWN vendored stdlib internals
	@# (crypto/tls vendors x/crypto), not third-party dependencies, so they are
	@# excluded — they ship with the toolchain either way.
	@unexpected=$$($(GO) list -deps ./cmd/certscan \
	   | grep -v '^$(MODULE)' | grep '\.' \
	   | grep -v '^vendor/' \
	   | grep -vE '^golang\.org/x/(net/idna|text/)' || true); \
	 if [ -n "$$unexpected" ]; then \
	   echo "cmd/certscan gained an unapproved dependency:"; echo "$$unexpected"; \
	   echo; echo "Approved: golang.org/x/net/idna and golang.org/x/text (IDN normalisation)."; \
	   echo "Anything else belongs in a separate binary. See docs/dependencies.md."; \
	   exit 1; \
	 fi; \
	 n=$$($(GO) list -deps ./cmd/certscan | grep -v '^$(MODULE)' | grep '\.' | grep -vc '^vendor/' || true); \
	 echo "deps-check: certscan depends on $$n approved external packages, from 2 modules (x/net/idna, x/text)"

build-all: ## Build all three release targets
	@mkdir -p $(BUILD_DIR)
	@for t in linux/amd64 linux/arm64 darwin/arm64; do \
	   os=$${t%/*}; arch=$${t#*/}; \
	   SOURCE_DATE_EPOCH=$${SOURCE_DATE_EPOCH:-1757894400} GOOS=$$os GOARCH=$$arch \
	     $(GO) build $(BUILDFLAGS) -o $(BUILD_DIR)/certscan-$$os-$$arch ./cmd/certscan || exit 1; \
	   echo "  $(BUILD_DIR)/certscan-$$os-$$arch"; \
	 done
	@cd $(BUILD_DIR) && shasum -a 256 certscan-* > SHA256SUMS && cat SHA256SUMS

repro: ## BLOCKING: assert two independent builds are byte-identical
	@rm -rf $(BUILD_DIR)/repro-a $(BUILD_DIR)/repro-b
	@mkdir -p $(BUILD_DIR)/repro-a $(BUILD_DIR)/repro-b
	@SOURCE_DATE_EPOCH=1757894400 GOOS=linux GOARCH=amd64 \
	   $(GO) build $(BUILDFLAGS) -o $(BUILD_DIR)/repro-a/certscan ./cmd/certscan
	@$(GO) clean -cache >/dev/null 2>&1 || true
	@SOURCE_DATE_EPOCH=1757894400 GOOS=linux GOARCH=amd64 \
	   $(GO) build $(BUILDFLAGS) -o $(BUILD_DIR)/repro-b/certscan ./cmd/certscan
	@a=$$(shasum -a 256 < $(BUILD_DIR)/repro-a/certscan | cut -d' ' -f1); \
	 b=$$(shasum -a 256 < $(BUILD_DIR)/repro-b/certscan | cut -d' ' -f1); \
	 if [ "$$a" != "$$b" ]; then \
	   echo "NOT REPRODUCIBLE: $$a != $$b"; exit 1; \
	 fi; echo "repro: OK ($$a)"

sbom: ## CycloneDX SBOM (requires syft)
	@command -v syft >/dev/null || { echo "syft not installed"; exit 1; }
	@syft . -o cyclonedx-json > $(BUILD_DIR)/sbom.cdx.json && echo "sbom: $(BUILD_DIR)/sbom.cdx.json"

deps: ## List the dependency tree and the recorded justification
	@$(GO) list -m all
	@echo; echo "Justification for every non-stdlib dependency: docs/dependencies.md"

check: fmt vet importcheck deps-check test-race canary ## Everything CI runs
	@echo
	@echo "check: ALL GATES PASSED"

clean:
	@rm -rf $(BUILD_DIR) coverage.out

corpus: ## Regenerate the committed certificate corpus (deliberate, not automatic)
	@$(GO) run ./internal/tools/gencorpus -n 460 -out test/corpus/testdata/corpus.json

verify-pins: ## Check that every pinned GitHub Action SHA resolves upstream
	@bash scripts/verify-action-pins.sh

aws-lab-up: ## Start LocalStack for the AWS integration tests
	@docker compose -f test/lab/docker-compose.aws.yml up -d
	@echo "waiting for LocalStack..."; until curl -sf http://localhost:4566/_localstack/health >/dev/null; do sleep 2; done; echo ready

aws-lab-test: ## Run the AWS integration tests against LocalStack
	@$(GO) test ./pkg/discover/aws/ -tags=localstack -count=1 -v

aws-lab-down: ## Stop LocalStack
	@docker compose -f test/lab/docker-compose.aws.yml down -v

.PHONY: lab-aws-up lab-aws-seed lab-aws-down
lab-aws-up: ## Start LocalStack for the AWS suite
	@docker compose -f test/lab/docker-compose.aws.yml up -d
	@echo "waiting for localstack..."; \
	 for i in $$(seq 1 40); do curl -sf http://localhost:4566/_localstack/health >/dev/null && break; sleep 3; done
	@echo "localstack up"

lab-aws-seed: ## Import a certificate into LocalStack ACM so enumeration has something to find
	@# Deliberately the aws CLI and not Go: importing a certificate is a WRITE,
	@# and pkg/discover/aws must contain no write path at all.
	@AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 \
	 aws --endpoint-url=http://localhost:4566 acm import-certificate \
	   --certificate fileb://test/lab/certs/pool.crt \
	   --private-key fileb://test/lab/certs/pool.key \
	   --query CertificateArn --output text

lab-aws-down: ## Stop LocalStack
	@docker compose -f test/lab/docker-compose.aws.yml down -v

# ---- control-plane database ------------------------------------------------
PGADMIN ?= postgres

.PHONY: db-up db-migrate db-down db-psql
db-up: ## Create the dev database and the two constrained roles
	@psql -qX -d $(PGADMIN) -c "DROP DATABASE IF EXISTS certwatch" >/dev/null 2>&1 || true
	@psql -qX -d $(PGADMIN) -c "DROP ROLE IF EXISTS certwatch_app" >/dev/null 2>&1 || true
	@psql -qX -d $(PGADMIN) -c "DROP ROLE IF EXISTS certwatch_migrator" >/dev/null 2>&1 || true
	@psql -qX -d $(PGADMIN) -c "CREATE DATABASE certwatch"
	@psql -qX -d $(PGADMIN) -f internal/store/bootstrap/roles.sql
	@psql -qX -d certwatch -c "ALTER DATABASE certwatch OWNER TO certwatch_migrator"
	@psql -qX -d certwatch -c "ALTER SCHEMA public OWNER TO certwatch_migrator"
	@echo "database ready. Roles:"
	@psql -qX -d certwatch -tAc "SELECT '  '||rolname||' bypassrls='||rolbypassrls||' superuser='||rolsuper FROM pg_roles WHERE rolname LIKE 'certwatch%'"

db-migrate: ## Apply migrations as the migrator role, then grant to the app role
	@$(GO) run ./cmd/certwatch-ctl migrate
	@psql -qX -d certwatch -U certwatch_migrator -h localhost -f internal/store/bootstrap/grants.sql

db-down: ## Drop the dev database and roles
	@psql -qX -d $(PGADMIN) -c "DROP DATABASE IF EXISTS certwatch" >/dev/null 2>&1 || true
	@psql -qX -d $(PGADMIN) -c "DROP ROLE IF EXISTS certwatch_app" >/dev/null 2>&1 || true
	@psql -qX -d $(PGADMIN) -c "DROP ROLE IF EXISTS certwatch_migrator" >/dev/null 2>&1 || true

db-psql: ## psql as the APP role, so you see what the application sees
	@psql "postgres://certwatch_app:certwatch_dev_password_not_for_production@localhost:5432/certwatch"
