PROJECTNAME := $(shell basename "$(PWD)")
GOBASE := $(shell pwd)
GOPATH := $(GOBASE):~/go
GOBIN := $(GOBASE)/bin
GOFILES := $(wildcard *.go) $(wildcard */*.go)

LDFLAGS=-ldflags "-s -w"

all: client

client:
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go build $(LDFLAGS) -v -o $(GOBIN)/client $(GOFILES)

install: client
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go install $(GOFILES)

clean:
	rm -f $(GOBIN)/client

.PHONY: all clean install
