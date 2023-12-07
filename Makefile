TARGET   ?= build/bettercap
PACKAGES ?= core firewall log modules network packets session tls
PREFIX   ?= /usr/local
GO       ?= go
VERSION := $(shell sed -n 's/Version[[:space:]]*=[[:space:]]*"\([0-9.]\+\)"/\1/p' core/banner.go)

all: build

build: resources
	$(GO) build -o $(TARGET) .

build_with_race_detector: resources
	$(GOFLAGS) $(GO) build -race -o $(TARGET) .

resources: network/manuf.go

network/manuf.go:
	@python3 ./network/make_manuf.py

install:
	@mkdir -p $(DESTDIR)$(PREFIX)/share/bettercap/caplets
	@cp $(TARGET) $(DESTDIR)$(PREFIX)/bin/

docker:
	@docker build -t bettercap:latest .

test:
	$(GOFLAGS) $(GO) test -covermode=atomic -coverprofile=cover.out ./...

html_coverage: test
	$(GOFLAGS) $(GO) tool cover -html=cover.out -o cover.out.html

benchmark: server_deps
	$(GOFLAGS) $(GO) test -v -run=doNotRunTests -bench=. -benchmem ./...

fmt:
	$(GO) fmt -s -w $(PACKAGES)

clean:
	@rm -rf build

.PHONY: all build build_with_race_detector resources install docker test html_coverage benchmark fmt clean