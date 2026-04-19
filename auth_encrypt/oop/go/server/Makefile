PROJECTNAME := $(shell basename "$(PWD)")
GOBASE := $(shell pwd)
GOPATH := $(GOBASE):~/go
GOBIN := $(GOBASE)/bin
GOFILES := $(wildcard *.go) $(wildcard */*.go)

LDFLAGS=-ldflags "-s -w"

all: server

server:
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go build $(LDFLAGS) -v -o $(GOBIN)/server $(GOFILES)

install: server
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go install $(GOFILES)

clean:
	rm -f $(GOBIN)/server

.PHONY: all clean install
