GO ?= go
BIN_DIR ?= bin

.PHONY: fmt test vet build check

fmt:
	$(GO)fmt -w $$(find . -type f -name '*.go' -not -path './.git/*')

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -o $(BIN_DIR)/adapterd ./cmd/adapterd

check: fmt test vet build
