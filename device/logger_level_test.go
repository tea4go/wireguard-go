package device

import (
	"reflect"
	"testing"

	logs "github.com/tea4go/gh/log4go"
)

func TestDeviceLogLevelsAlignWithLog4go(t *testing.T) {
	if LogLevelEmergency != logs.LevelEmergency {
		t.Fatalf("LogLevelEmergency = %d, want %d", LogLevelEmergency, logs.LevelEmergency)
	}
	if LogLevelAlert != logs.LevelAlert {
		t.Fatalf("LogLevelAlert = %d, want %d", LogLevelAlert, logs.LevelAlert)
	}
	if LogLevelCritical != logs.LevelCritical {
		t.Fatalf("LogLevelCritical = %d, want %d", LogLevelCritical, logs.LevelCritical)
	}
	if LogLevelError != logs.LevelError {
		t.Fatalf("LogLevelError = %d, want %d", LogLevelError, logs.LevelError)
	}
	if LogLevelWarning != logs.LevelWarning {
		t.Fatalf("LogLevelWarning = %d, want %d", LogLevelWarning, logs.LevelWarning)
	}
	if LogLevelNotice != logs.LevelNotice {
		t.Fatalf("LogLevelNotice = %d, want %d", LogLevelNotice, logs.LevelNotice)
	}
	if LogLevelInfo != logs.LevelInfo {
		t.Fatalf("LogLevelInfo = %d, want %d", LogLevelInfo, logs.LevelInfo)
	}
	if LogLevelVerbose != logs.LevelDebug {
		t.Fatalf("LogLevelVerbose = %d, want %d", LogLevelVerbose, logs.LevelDebug)
	}
}

func TestNewLoggerEnablesFunctionsAtAlignedThresholds(t *testing.T) {
	discardPtr := reflect.ValueOf(DiscardLogf).Pointer()

	warningLogger := NewLogger(logs.LevelWarning, "wg0")
	if reflect.ValueOf(warningLogger.Warningf).Pointer() == discardPtr {
		t.Fatal("warning logger should enable Warningf at LevelWarning")
	}
	if reflect.ValueOf(warningLogger.Notice).Pointer() != discardPtr {
		t.Fatal("warning logger should not enable Notice below LevelNotice")
	}

	noticeLogger := NewLogger(logs.LevelNotice, "wg0")
	if reflect.ValueOf(noticeLogger.Notice).Pointer() == discardPtr {
		t.Fatal("notice logger should enable Notice at LevelNotice")
	}
	if reflect.ValueOf(noticeLogger.Info).Pointer() != discardPtr {
		t.Fatal("notice logger should not enable Info below LevelInfo")
	}

	infoLogger := NewLogger(logs.LevelInfo, "wg0")
	if reflect.ValueOf(infoLogger.Info).Pointer() == discardPtr {
		t.Fatal("info logger should enable Info at LevelInfo")
	}
	if reflect.ValueOf(infoLogger.Debug).Pointer() != discardPtr {
		t.Fatal("info logger should not enable Debug below LevelDebug")
	}

	debugLogger := NewLogger(logs.LevelDebug, "wg0")
	if reflect.ValueOf(debugLogger.Debug).Pointer() == discardPtr {
		t.Fatal("debug logger should enable Debug at LevelDebug")
	}
	if reflect.ValueOf(debugLogger.Verbosef).Pointer() == discardPtr {
		t.Fatal("debug logger should enable Verbosef at LevelDebug")
	}
}
