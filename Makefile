PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin

# 版本号：优先从外部注入，例如 `make VERSION=v1.2.3`，否则通过 git describe 自动推导，兜底为 v0.0.0-devel
VERSION ?= $(shell export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" ; git describe --dirty --always --tags 2>/dev/null || echo "v0.0.0-devel")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
IS_BETA ?=

# Go 工具链参数
export GO111MODULE := on
GO ?= go
export CGO_ENABLED ?= 0

# 构建产物名
BIN_NAME ?= wireguard-go
WIN_BIN_NAME ?= wireguard-go.exe

# 注入到 main 包的链接参数（两个入口：main.runtimeVersion 用于 POSIX，main.appVer 用于 Windows）
LDFLAGS_COMMON := -s -w
LDFLAGS_VERSION := -X main.runtimeVersion=$(VERSION) -X main.appVer=$(VERSION) -X main.BuildTime=$(BUILD_TIME)
ifneq ($(IS_BETA),)
LDFLAGS_VERSION += -X main.IsBeta=$(IS_BETA)
endif
LDFLAGS := $(LDFLAGS_COMMON) $(LDFLAGS_VERSION)

MAKEFLAGS += --no-print-directory

# 默认目标：不写 version.go，直接通过 ldflags 注入版本号后构建
all: wireguard-go

# 兜底：当 go 源码改动需要版本号出现在二进制里时，仍然可以调用此目标生成 version.go（兼容老流程）
generate-version:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null || echo $(VERSION))" && \
	ver="$$(printf 'package main\n\nconst Version = "%s"\n' "$$tag")" && \
	( [ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && echo "$$ver" > version.go && \
	git update-index --assume-unchanged version.go || true )

# POSIX 平台构建（使用 ldflags 注入，不需要再写 version.go；若源码显式引用了常量 Version 则会回退到 version.go）
wireguard-go: $(wildcard *.go) $(wildcard */*.go)
	@echo "构建 $(BIN_NAME) version=$(VERSION) build_time=$(BUILD_TIME)"
	$(GO) build -v -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o "$@"

# 交叉编译 Windows (amd64)
windows-amd64:
	@echo "构建 $(WIN_BIN_NAME) version=$(VERSION) GOOS=windows GOARCH=amd64"
	GOOS=windows GOARCH=amd64 $(GO) build -v -trimpath -buildvcs=false \
		-ldflags '$(LDFLAGS)' -o "$(WIN_BIN_NAME)"

# 交叉编译 Windows (arm64)
windows-arm64:
	@echo "构建 $(WIN_BIN_NAME) version=$(VERSION) GOOS=windows GOARCH=arm64"
	GOOS=windows GOARCH=arm64 $(GO) build -v -trimpath -buildvcs=false \
		-ldflags '$(LDFLAGS)' -o "wireguard-go-arm64.exe"

# 全平台（方便打包发布）
release: wireguard-go windows-amd64 windows-arm64
	@echo "发布产物已生成：$(BIN_NAME) / $(WIN_BIN_NAME) / wireguard-go-arm64.exe"

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/$(BIN_NAME)"

test:
	$(GO) test -v ./...

vet:
	$(GO) vet ./...

clean:
	rm -f wireguard-go wireguard-go.exe wireguard-go-arm64.exe wireguard.exe

# 调试：展示当前 Makefile 解析到的版本号与 ldflags
showenv:
	@echo "VERSION     = $(VERSION)"
	@echo "BUILD_TIME  = $(BUILD_TIME)"
	@echo "IS_BETA     = $(IS_BETA)"
	@echo "LDFLAGS     = $(LDFLAGS)"
	@echo "GO          = $(GO)"
	@echo "GOOS        = $(shell $(GO) env GOOS)"
	@echo "GOARCH      = $(shell $(GO) env GOARCH)"

.PHONY: all generate-version windows-amd64 windows-arm64 release install test vet clean showenv
