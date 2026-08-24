PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin

# Version (do NOT derive from git anymore - auto-increment persisted in VERSION.txt).
#
#   Priority:
#     1) `make VERSION=vx.y.z`            -> use VERSION, and save it into VERSION.txt
#     2) else read VERSION.txt (default start v3.0.0 if missing)
#        increment PATCH with carry: each digit max = 9
#          e.g. v3.0.9 -> v3.1.0 ; v3.9.9 -> v4.0.0
#        save the new VERSION.txt

VERSION_FILE := $(CURDIR)/VERSION.txt

# If caller passed VERSION=..., use it as-is and persist.
ifdef VERSION
  APP_TAG := $(VERSION)
  $(shell printf '%s\n' '$(APP_TAG)' > '$(VERSION_FILE)')
else
  APP_TAG := $(shell \
    CUR=`cat '$(VERSION_FILE)' 2>/dev/null || echo v3.0.0`; \
    CUR=$${CUR\#v}; CUR=$${CUR// /}; \
    CUR=$${CUR%%-*}; CUR=$${CUR%%_*}; \
    MA=3; MI=0; PA=0; \
    IFS=. read -r _MA _MI _PA <<TXT
$$CUR
TXT
    _MA=$${_MA//[^0-9]/}; _MI=$${_MI//[^0-9]/}; _PA=$${_PA//[^0-9]/}; \
    [ -n "$$_MA" ] && MA=$$_MA; \
    [ -n "$$_MI" ] && MI=$$_MI; \
    [ -n "$$_PA" ] && PA=$$_PA; \
    MA=$$((MA+0)); MI=$$((MI+0)); PA=$$((PA+0)); \
    PA=$$((PA+1)); \
    if [ $$PA -gt 9 ]; then PA=0; MI=$$((MI+1)); fi; \
    if [ $$MI -gt 9 ]; then MI=0; MA=$$((MA+1)); fi; \
    NEW="v$$MA.$$MI.$$PA"; \
    printf '%s\n' "$$NEW" > '$(VERSION_FILE)'; \
    printf '%s' "$$NEW")
endif

# Final composed version strings
BUILD_DATE ?= $(shell date -u +%Y%m%d)
BUILD_HHMM ?= $(shell date -u +%H%M)
# APP_VER_FULL: IS_BETA=true -> v3.0.1_B20060930_0930 ; IS_BETA empty/false -> v3.0.1
ifdef IS_BETA
  APP_VER_FULL ?= $(APP_TAG)_B$(BUILD_DATE)_$(BUILD_HHMM)
else
  APP_VER_FULL ?= $(APP_TAG)
endif
BUILD_TIME ?= $(shell date -u '+%Y-%m-%d(%H:%M:%S)')
IS_BETA ?=

# Go toolchain settings
export GO111MODULE := on
GO ?= go
export CGO_ENABLED ?= 0

# Output binaries
BIN_NAME ?= wireguard-go
WIN_BIN_NAME ?= wireguard-go.exe

# ldflags injected into package main
LDFLAGS_COMMON := -s -w
LDFLAGS_VERSION := -X main.runtimeVersion=$(APP_VER_FULL) -X main.appVer=$(APP_VER_FULL) -X "main.BuildTime=$(BUILD_TIME)"
ifneq ($(IS_BETA),)
LDFLAGS_VERSION += -X main.IsBeta=$(IS_BETA)
endif
LDFLAGS := $(LDFLAGS_COMMON) $(LDFLAGS_VERSION)

MAKEFLAGS += --no-print-directory

# Default target: build POSIX wireguard-go
all: wireguard-go

# POSIX build
wireguard-go: $(wildcard *.go) $(wildcard */*.go)
	@echo "Building $(BIN_NAME) APP_TAG=$(APP_TAG) APP_VER_FULL=$(APP_VER_FULL) BUILD_TIME=$(BUILD_TIME)"
	$(GO) build -v -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o "$@"

# Cross-compile Windows amd64
windows-amd64:
	@echo "Building $(WIN_BIN_NAME) APP_TAG=$(APP_TAG) GOOS=windows GOARCH=amd64"
	GOOS=windows GOARCH=amd64 $(GO) build -v -trimpath -buildvcs=false \
		-ldflags '$(LDFLAGS)' -o "$(WIN_BIN_NAME)"

# Cross-compile Windows arm64
windows-arm64:
	@echo "Building wireguard-go-arm64.exe APP_TAG=$(APP_TAG) GOOS=windows GOARCH=arm64"
	GOOS=windows GOARCH=arm64 $(GO) build -v -trimpath -buildvcs=false \
		-ldflags '$(LDFLAGS)' -o "wireguard-go-arm64.exe"

# Convenience: all three platform binaries
release: wireguard-go windows-amd64 windows-arm64
	@echo "Release artifacts: $(BIN_NAME) / $(WIN_BIN_NAME) / wireguard-go-arm64.exe"

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/$(BIN_NAME)"

test:
	$(GO) test -v ./...

vet:
	$(GO) vet ./...

clean:
	rm -f wireguard-go wireguard-go.exe wireguard-go-arm64.exe wireguard.exe

# Debug: print resolved version / env
showenv:
	@echo "VERSION_FILE = $(VERSION_FILE)"
	@echo "APP_TAG      = $(APP_TAG)       (MAJOR.MINOR.PATCH, each digit max=9, carry to next)"
	@echo "BUILD_DATE   = $(BUILD_DATE)   (YYYYMMDD)"
	@echo "BUILD_HHMM   = $(BUILD_HHMM)   (HHmm)"
ifdef IS_BETA
	@echo "APP_VER_FULL = $(APP_VER_FULL)   (IS_BETA set: v3.0.1_B20060930_0930)"
else
	@echo "APP_VER_FULL = $(APP_VER_FULL)   (IS_BETA empty: v3.0.1 only)"
endif
	@echo "BUILD_TIME   = $(BUILD_TIME)   (yyyy-mm-dd(hh:mm:ss))"
	@echo "IS_BETA      = $(IS_BETA)"
	@echo "LDFLAGS      = $(LDFLAGS)"
	@echo "GO           = $(GO)"
	@echo "GOOS         = $(shell $(GO) env GOOS)"
	@echo "GOARCH       = $(shell $(GO) env GOARCH)"

.PHONY: all windows-amd64 windows-arm64 release install test vet clean showenv
