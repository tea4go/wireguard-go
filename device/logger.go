/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	logs "github.com/tea4go/gh/log4go"
)

// Logger 封装 WireGuard Device 使用的分级日志函数指针。
// 所有方法均采用 Printf 风格（format + args），与 log4go 各级别 API 一一对应。
type Logger struct {
	Verbosef   func(format string, args ...any) // 详细/调试日志，映射到 log4go 的 Debug 级别
	Debug      func(format string, args ...any) // 调试日志，
	Info       func(format string, args ...any) // 信息级别
	Notice     func(format string, args ...any) // 通知级别
	Warningf   func(format string, args ...any) // 警告级别
	Errorf     func(format string, args ...any) // 错误级别
	Criticalf  func(format string, args ...any) // 严重错误级别
	Alertf     func(format string, args ...any) // 警报级别
	Emergencyf func(format string, args ...any) // 紧急事故级别
	Printf     func(format string, args ...any) // 直接打印（无前缀）
}

// 日志级别开关常量，数字越大表示输出越详细。
// 通过 level >= 对应常量判断该级别及更严重级别是否启用。
const (
	LogLevelSilent    = iota // 0：静默，不输出任何日志
	LogLevelEmergency        // 1：紧急事故（系统不可用）
	LogLevelAlert            // 2：警报（需要立即采取行动）
	LogLevelCritical         // 3：严重错误
	LogLevelError            // 4：错误（默认级别）
	LogLevelWarning          // 5：警告
	LogLevelNotice           // 6：通知（重要信息）
	LogLevelInfo             // 7：一般信息
	LogLevelVerbose          // 8：详细/调试信息，对应 log4go Debug 级别
	LogLevelPrint            // 9：直接打印，无前缀
)

// DiscardLogf 空日志函数，用于关闭某一级别的日志输出。
func DiscardLogf(format string, args ...any) {}

// NewLogger 根据指定的日志级别构造带前缀的 Logger。
//
// 参数：
//   - level   ：日志级别开关（LogLevel* 常量），数字越大输出越详细；
//     level >= 对应级别常量时，该级别及更严重级别的日志才会输出。
//   - prepend ：每条日志前自动附加的前缀字符串（例如接口名 "(wg0) "）。
//
// 各级别与 log4go 的映射关系：
//   - Emergencyf → logs.Emergency
//   - Alertf     → logs.Alert
//   - Criticalf  → logs.Critical
//   - Errorf     → logs.Error
//   - Warningf   → logs.Warning
//   - Notice     → logs.Notice
//   - Info       → logs.Info
//   - Verbosef   → logs.Debug
//   - Printf     → logs.Print
func NewLogger(level int, prepend string) *Logger {
	// 默认将所有级别指向 DiscardLogf（丢弃），后续按 level 逐个启用
	logger := &Logger{
		Verbosef:   DiscardLogf,
		Debug:      DiscardLogf,
		Info:       DiscardLogf,
		Notice:     DiscardLogf,
		Warningf:   DiscardLogf,
		Errorf:     DiscardLogf,
		Criticalf:  DiscardLogf,
		Alertf:     DiscardLogf,
		Emergencyf: DiscardLogf,
		Printf:     DiscardLogf,
	}

	// 前缀格式化辅助函数：自动拼接 "[" + prepend + "] "
	mkPrefix := func(format string) string {
		return "[" + prepend + "] " + format
	}

	// 9：Print 级别 → logs.Print（直接输出）
	if level >= LogLevelPrint {
		logger.Printf = func(format string, args ...any) {
			logs.Print(mkPrefix(format), args...)
		}
	}

	// 8：Verbose 级别 → logs.Debug
	if level >= LogLevelVerbose {
		logger.Verbosef = func(format string, args ...any) {
			logs.Debug(mkPrefix(format), args...)
		}
	}

	// 7：Info 级别 → logs.Info
	if level >= LogLevelInfo {
		logger.Info = func(format string, args ...any) {
			logs.Info(mkPrefix(format), args...)
		}
	}

	// 7：Debug 级别 → logs.Debug（与 Verbosef 同为调试输出，Debug 先于 Verbose 启用）
	if level >= LogLevelInfo {
		logger.Debug = func(format string, args ...any) {
			logs.Debug(mkPrefix(format), args...)
		}
	}

	// 6：Notice 级别 → logs.Notice
	if level >= LogLevelNotice {
		logger.Notice = func(format string, args ...any) {
			logs.Notice(mkPrefix(format), args...)
		}
	}

	// 5：Warning 级别 → logs.Warning
	if level >= LogLevelWarning {
		logger.Warningf = func(format string, args ...any) {
			logs.Warning(mkPrefix(format), args...)
		}
	}

	// 4：Error 级别 → logs.Error
	if level >= LogLevelError {
		logger.Errorf = func(format string, args ...any) {
			logs.Error(mkPrefix(format), args...)
		}
	}

	// 3：Critical 级别 → logs.Critical
	if level >= LogLevelCritical {
		logger.Criticalf = func(format string, args ...any) {
			logs.Critical(mkPrefix(format), args...)
		}
	}

	// 2：Alert 级别 → logs.Alert
	if level >= LogLevelAlert {
		logger.Alertf = func(format string, args ...any) {
			logs.Alert(mkPrefix(format), args...)
		}
	}

	// 1：Emergency 级别 → logs.Emergency
	if level >= LogLevelEmergency {
		logger.Emergencyf = func(format string, args ...any) {
			logs.Emergency(mkPrefix(format), args...)
		}
	}

	return logger
}
