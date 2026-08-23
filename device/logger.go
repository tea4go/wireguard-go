/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	logs "github.com/tea4go/gh/log4go"
)

type Logger struct {
	Verbosef func(format string, args ...any)
	Errorf   func(format string, args ...any)
}

const (
	LogLevelSilent = iota
	LogLevelError
	LogLevelVerbose
)

func DiscardLogf(format string, args ...any) {}

func NewLogger(level int, prepend string) *Logger {
	logger := &Logger{DiscardLogf, DiscardLogf}
	if level >= LogLevelVerbose {
		logger.Verbosef = func(format string, args ...any) {
			logs.Debug("["+prepend+"] "+format, args...)
		}
	}
	if level >= LogLevelError {
		logger.Errorf = func(format string, args ...any) {
			logs.Error("["+prepend+"] "+format, args...)
		}
	}
	return logger
}
