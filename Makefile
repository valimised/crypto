# IVXV Crypto Go project root dir
ROOTDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Golang version
GOLANG_VERSION := 1.23.0

# golangci-lint version
GOLANGCI_LINT_VERSION := 2.0.2

.PHONY: help
help:
	@echo "usage: make test       Run tests"
	@echo "       make fuzz       Run fuzzing"
	@echo "       make lint       Run linter"

# Test Go packages
.PHONY: test
test:
	docker run --rm -v $(ROOTDIR):/gotest -w /gotest golang:$(GOLANG_VERSION) go test -v /gotest/...

# Fuzz Go packages
.PHONY: fuzz
fuzz:

# Lint Go packages
.PHONY: lint
lint:
	docker run --rm -v $(ROOTDIR):/golint -w /golint golangci/golangci-lint:v$(GOLANGCI_LINT_VERSION) golangci-lint run
