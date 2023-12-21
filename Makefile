TARGET   ?= build/bettercap
PACKAGES ?= core firewall log modules network packets session tls
PREFIX   ?= /usr/local
VERSION := $(shell sed -n 's/Version[[:space:]]*=[[:space:]]*"\([0-9.]\+\)"/\1/p' core/banner.go)

all: build

build: resources
	go build -o $(TARGET) .

build_with_race_detector: resources
	$(GOFLAGS) go build -race -o $(TARGET) .

resources: network/manuf.go

network/manuf.go:
	@python3 ./network/make_manuf.py

install:
	@mkdir -p $(DESTDIR)$(PREFIX)/share/bettercap/caplets
	@cp $(TARGET) $(DESTDIR)$(PREFIX)/bin/

docker:
	@docker build -t bettercap:latest .

test:
	$(GOFLAGS) go test -covermode=atomic -coverprofile=cover.out ./...

html_coverage: test
	$(GOFLAGS) go tool cover -html=cover.out -o cover.out.html

benchmark: server_deps
	$(GOFLAGS) go test -v -run=doNotRunTests -bench=. -benchmem ./...

fmt:
	$(GO) fmt -s -w $(PACKAGES)

clean:
	@rm -rf build

release_files: clean
    # shellcheck disable=SC2086
	@mkdir build
	@echo building for linux/amd64 ...
	@CGO_ENABLED=1 GOARCH=amd64 GOOS=linux $(MAKE) build
	@openssl dgst -sha256 "build/bettercap" > "build/bettercap-amd64.sha256"
	@zip -j "build/bettercap-$(VERSION)-amd64.zip" build/bettercap build/bettercap-amd64.sha256 > /dev/null
	@rm -rf build/bettercap build/bettercap-amd64.sha256
	@echo building for linux/armhf ...
	@CGO_ENABLED=1 CC=arm-linux-gnueabihf-gcc GOARM=6 GOARCH=arm GOOS=linux $(MAKE) build
	@openssl dgst -sha256 "build/bettercap" > "build/bettercap-armhf.sha256"
	@zip -j "build/bettercap-$(VERSION)-armhf.zip" build/bettercap build/bettercap-armhf.sha256 > /dev/null
	@rm -rf build/pwngrid build/bettercap-armhf.sha256
	@echo building for linux/aarch64 ...
	@CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc GOARCH=arm64 GOOS=linux $(MAKE) build
	@openssl dgst -sha256 "build/bettercap" > "build/bettercap-aarch64.sha256"
	@zip -j "build/bettercap-$(VERSION)-aarch64.zip" build/bettercap build/bettercap-aarch64.sha256 > /dev/null
	@rm -rf build/pwngrid build/bettercap-aarch64.sha256
	@ls -la build

.PHONY: all build build_with_race_detector resources install docker test html_coverage benchmark fmt clean release_files