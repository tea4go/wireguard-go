/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"log"
	"os"
	"time"
)

// Logger 为 Device 提供日志记录能力。
// 其函数成员均为 Printf 风格函数。
// 它们必须支持并发安全使用。
// 格式字符串末尾无需附带换行符。
// 若为 nil，对应级别的日志将被静默丢弃。
type Logger struct {
	Verbosef func(format string, args ...any)
	Errorf   func(format string, args ...any)
}

// 供 NewLogger 使用的日志级别。
const (
	LogLevelSilent = iota
	LogLevelError
	LogLevelVerbose
)

// DiscardLogf 用于 Logger 中丢弃日志行的空操作函数。
func DiscardLogf(format string, args ...any) {}

// NewLogger 构造一个将日志写入标准输出（stdout）的 Logger。
// 仅记录指定级别及以上的日志。
// 每条日志会附加日志级别、日期（yyyy-mm-dd 格式）、时间以及 prepend 前缀。
func NewLogger(level int, prepend string) *Logger {
	logger := &Logger{DiscardLogf, DiscardLogf}
	logf := func(prefix string) func(string, ...any) {
		l := log.New(os.Stdout, "", 0)
		return func(format string, args ...any) {
			// 日期采用 yyyy-mm-dd 格式（Go 布局参考时间为 2006-01-02）
			l.Printf("%s %s > [%s] %s", time.Now().Format("2006-01-02 15:04:05"), prefix, prepend, fmt.Sprintf(format, args...))
		}
	}
	if level >= LogLevelVerbose {
		logger.Verbosef = logf("[D]")
	}
	if level >= LogLevelError {
		logger.Errorf = logf("[E]")
	}
	return logger
}
