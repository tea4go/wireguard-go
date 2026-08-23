/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

const DefaultMTU = 1420

func (device *Device) RoutineTUNEventReader() {
	device.log.Verbosef("例程：事件工作线程 - 已启动")

	for event := range device.tun.device.Events() {
		if event&tun.EventMTUUpdate != 0 {
			mtu, err := device.tun.device.MTU()
			if err != nil {
				device.log.Errorf("加载设备更新后的 MTU 失败, %v", err)
				continue
			}
			if mtu < 0 {
				device.log.Errorf("MTU 未更新为负值, %v", mtu)
				continue
			}
			var tooLarge string
			if mtu > MaxContentSize {
				tooLarge = fmt.Sprintf("（过大，已限制为 %v）", MaxContentSize)
				mtu = MaxContentSize
			}
			old := device.tun.mtu.Swap(int32(mtu))
			if int(old) != mtu {
				device.log.Verbosef("MTU 已更新, %v%s", mtu, tooLarge)
			}
		}

		if event&tun.EventUp != 0 {
			device.log.Verbosef("收到接口启动请求")
			device.Up()
		}

		if event&tun.EventDown != 0 {
			device.log.Verbosef("收到接口停止请求")
			device.Down()
		}
	}

	device.log.Verbosef("例程：事件工作线程 - 已停止")
}
