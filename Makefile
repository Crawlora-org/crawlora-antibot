BINARY  := crawlora-antibot
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"

.PHONY: build test vet fmt install clean

build:
	go build $(LDFLAGS) -o $(BINARY) .

test:
	go test ./... -count=1

vet:
	go vet ./...

fmt:
	gofmt -w .

install:
	go install $(LDFLAGS) .

clean:
	rm -f $(BINARY) cab
