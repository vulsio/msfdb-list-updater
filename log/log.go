package log

import (
	"fmt"

	logger "github.com/inconshreveable/log15"
)

// Debugf is wrapper function
func Debugf(format string, args ...interface{}) {
	logger.Debug(fmt.Sprintf(format, args...))
}

// Infof is wrapper function
func Infof(format string, args ...interface{}) {
	logger.Info(fmt.Sprintf(format, args...))
}

// Warnf is wrapper function
func Warnf(format string, args ...interface{}) {
	logger.Warn(fmt.Sprintf(format, args...))
}

// Errorf is wrapper function
func Errorf(format string, args ...interface{}) {
	logger.Error(fmt.Sprintf(format, args...))
}

// Fatalf is wrapper function
func Fatalf(format string, args ...interface{}) {
	logger.Crit(fmt.Sprintf(format, args...))
}
