package util

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var (
	ProjectPath string
	LogDate     string
	NoState     bool
)

func LogInfo(msg string) {
	lMsg := LogMessage("INFO", msg)
	if !NoState {
		writeLogToFile(lMsg)
	}
	fmt.Print(lMsg)
}

func LogErr(msg string) {
	lMsg := LogMessage("ERROR", msg)
	if !NoState {
		writeLogToFile(lMsg)
	}
	fmt.Print(lMsg)
}

func LogVerbose(msg string) {
	lMsg := LogMessage("VERBOSE", msg)
	if !NoState {
		writeLogToFile(lMsg)
	}
	fmt.Print(lMsg)
}

func LogMessage(label string, msg string) string {
	ct := time.Now()
	return fmt.Sprintf("[%s] [%s] %s\n", ct.Format("15:04:05"), label, msg)
}

func LogVulnerable(msg string) {
	if !NoState {
		writeLogToFile(msg)
	}
}

func writeLogToFile(msg string) {
	logFilePath := filepath.Join(ProjectPath, (LogDate + "-log.log"))

	f, err := os.OpenFile(logFilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		fmt.Printf("Unable to create or open log file: %s\n", err)
		return
	}

	defer f.Close()

	if _, err := f.WriteString(msg); err != nil {
		fmt.Printf("Unable to write to log file\n")
		return
	}
}
