# [WireGuard](https://www.wireguard.com/) 的 Go 语言实现

这是 WireGuard 的 Go 语言实现。

> 📖 **其他语言版本**: [English](README.md)

## 使用方法

大多数 Linux 内核 WireGuard 用户习惯于通过 `ip link add wg0 type wireguard` 来添加接口。使用 wireguard-go 时，只需运行：

```
$ wireguard-go wg0
```

这将创建一个接口并 fork 到后台运行。要移除接口，可以使用常规的 `ip link del wg0` 命令，或者如果你的系统不支持直接移除接口，可以通过 `rm -f /var/run/wireguard/wg0.sock` 移除控制套接字，这将使 wireguard-go 关闭。

要在不 fork 到后台的情况下运行 wireguard-go，请传递 `-f` 或 `--foreground` 参数：

```
$ wireguard-go -f wg0
```

当接口运行时，你可以使用 [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) 来配置它，也可以使用常规的 `ip(8)` 和 `ifconfig(8)` 命令。

要获取更多日志输出，可以设置环境变量 `LOG_LEVEL=debug`。

## 平台支持

### Linux

此程序可以在 Linux 上运行；但是，你应该优先使用内核模块，它速度更快且与操作系统集成得更好。请参阅[安装页面](https://www.wireguard.com/install/)获取说明。

### macOS

此程序使用 utun 驱动在 macOS 上运行。它目前不支持 sticky socket，并且由于 Darwin 的限制，不支持 fwmark。由于 utun 驱动不能使用任意接口名称，你必须使用 `utun[0-9]+` 作为显式接口名称，或者使用 `utun` 让内核自动选择一个。如果你选择 `utun` 作为接口名称，并且定义了环境变量 `WG_TUN_NAME_FILE`，那么内核选择的实际接口名称将被写入该变量指定的文件中。

### Windows

此程序可以在 Windows 上运行，但你应该通过[功能更完善的 Windows 应用](https://git.zx2c4.com/wireguard-windows/about/)来使用它，该应用将此作为模块使用。

### FreeBSD

此程序可以在 FreeBSD 上运行。它目前不支持 sticky socket。Fwmark 被映射到 `SO_USER_COOKIE`。

### OpenBSD

此程序可以在 OpenBSD 上运行。它目前不支持 sticky socket。Fwmark 被映射到 `SO_RTABLE`。由于 tun 驱动不能使用任意接口名称，你必须使用 `tun[0-9]+` 作为显式接口名称，或者使用 `tun` 让程序自动选择一个。如果你选择 `tun` 作为接口名称，并且定义了环境变量 `WG_TUN_NAME_FILE`，那么内核选择的实际接口名称将被写入该变量指定的文件中。

## 构建

这需要安装最新版本的 [Go](https://go.dev/)。

```
$ git clone https://git.zx2c4.com/wireguard-go
$ cd wireguard-go
$ make
```

## 许可证

    Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.