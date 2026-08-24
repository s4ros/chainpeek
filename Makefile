GO ?= go
BIN := bin/chainpeek

.PHONY: build test run fmt vet tidy clean

build:
	$(GO) build -o $(BIN) ./cmd/chainpeek

test:
	$(GO) test ./...

run: build
	./$(BIN) --file testdata/filter.rules

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf bin
