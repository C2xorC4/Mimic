package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Level represents log severity
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel parses a log level string
func ParseLevel(s string) Level {
	switch s {
	case "debug", "DEBUG":
		return LevelDebug
	case "info", "INFO":
		return LevelInfo
	case "warn", "WARN", "warning", "WARNING":
		return LevelWarn
	case "error", "ERROR":
		return LevelError
	default:
		return LevelInfo
	}
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Component string                 `json:"component,omitempty"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// Logger handles structured logging
type Logger struct {
	mu           sync.Mutex
	level        Level
	component    string
	file         *os.File
	fileJSON     bool // JSON format for file output
	writeToFile  bool
	writeStdout  bool
}

// Config holds logger configuration
type Config struct {
	Level    string `yaml:"level"`
	LogDir   string `yaml:"log_dir"`
	JSONMode bool   `yaml:"json_mode"` // JSON format for file logs (stdout is always human-readable)
	ToStdout bool   `yaml:"to_stdout"` // Also output to stdout (human-readable)
}

// DefaultConfig returns default logging configuration
func DefaultConfig() Config {
	return Config{
		Level:    "info",
		LogDir:   "/var/log/mimic",
		JSONMode: true,
		ToStdout: true,
	}
}

// DefaultFallbackDir is used when the primary log directory is not writable
const DefaultFallbackDir = "./log/mimic"

var (
	defaultLogger *Logger
	probeLogger   *Logger
	loggerMu      sync.Mutex
	activeLogDir  string // Track the actual log directory being used
)

// GetActiveLogDir returns the directory where logs are being written
func GetActiveLogDir() string {
	loggerMu.Lock()
	defer loggerMu.Unlock()
	return activeLogDir
}

// Init initializes the global loggers
func Init(cfg Config) error {
	loggerMu.Lock()
	defer loggerMu.Unlock()

	var fallbackReason string
	originalDir := cfg.LogDir

	// Try to create the configured log directory
	if cfg.LogDir != "" {
		if err := os.MkdirAll(cfg.LogDir, 0755); err != nil {
			fallbackReason = fmt.Sprintf("Failed to create log directory %s: %v", cfg.LogDir, err)

			// Fall back to ./log/mimic
			cfg.LogDir = DefaultFallbackDir
			if err := os.MkdirAll(cfg.LogDir, 0755); err != nil {
				return fmt.Errorf("creating fallback log directory %s: %w", cfg.LogDir, err)
			}
		} else {
			// Directory exists or was created, verify we can write to it
			testFile := filepath.Join(cfg.LogDir, ".write_test")
			if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
				fallbackReason = fmt.Sprintf("Cannot write to log directory %s: %v", cfg.LogDir, err)

				// Fall back to ./log/mimic
				cfg.LogDir = DefaultFallbackDir
				if err := os.MkdirAll(cfg.LogDir, 0755); err != nil {
					return fmt.Errorf("creating fallback log directory %s: %w", cfg.LogDir, err)
				}
			} else {
				// Clean up test file
				os.Remove(testFile)
			}
		}
	}

	activeLogDir = cfg.LogDir
	level := ParseLevel(cfg.Level)

	// Initialize main logger
	var err error
	defaultLogger, err = newLogger(cfg, level, "mimic.log", "mimic")
	if err != nil {
		return fmt.Errorf("creating main logger: %w", err)
	}

	// Initialize probe logger (probes always go to file, optionally stdout)
	probeLogger, err = newLogger(cfg, LevelInfo, "probes.log", "probe")
	if err != nil {
		return fmt.Errorf("creating probe logger: %w", err)
	}

	// If we fell back to a different directory, log a warning as the first entry
	if fallbackReason != "" {
		defaultLogger.Warn("Log directory fallback", map[string]interface{}{
			"requested_dir": originalDir,
			"actual_dir":    cfg.LogDir,
			"reason":        fallbackReason,
		})
	}

	return nil
}

func newLogger(cfg Config, level Level, filename, component string) (*Logger, error) {
	l := &Logger{
		level:       level,
		component:   component,
		fileJSON:    cfg.JSONMode,
		writeStdout: cfg.ToStdout,
	}

	// Open file if log directory is set
	if cfg.LogDir != "" {
		path := filepath.Join(cfg.LogDir, filename)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("opening log file %s: %w", path, err)
		}
		l.file = f
		l.writeToFile = true
	}

	// Ensure we have at least one output
	if !l.writeToFile && !l.writeStdout {
		l.writeStdout = true
	}

	return l, nil
}

// Close closes the logger's file handle
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Shutdown closes all loggers
func Shutdown() {
	loggerMu.Lock()
	defer loggerMu.Unlock()

	if defaultLogger != nil {
		defaultLogger.Close()
	}
	if probeLogger != nil {
		probeLogger.Close()
	}
}

func (l *Logger) log(level Level, msg string, fields map[string]interface{}) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	entry := LogEntry{
		Timestamp: now.UTC().Format(time.RFC3339),
		Level:     level.String(),
		Component: l.component,
		Message:   msg,
		Fields:    fields,
	}

	// Write to file (JSON or human-readable based on config)
	if l.writeToFile && l.file != nil {
		if l.fileJSON {
			data, _ := json.Marshal(entry)
			fmt.Fprintln(l.file, string(data))
		} else {
			fmt.Fprintln(l.file, l.formatHuman(now, level, msg, fields))
		}
	}

	// Write to stdout (always human-readable for interactive debugging)
	if l.writeStdout {
		fmt.Println(l.formatHuman(now, level, msg, fields))
	}
}

// formatHuman creates a human-readable log line matching the original log.Printf style
func (l *Logger) formatHuman(t time.Time, level Level, msg string, fields map[string]interface{}) string {
	// Format: 2006/01/02 15:04:05 [LEVEL] [component] message key=value key=value
	timestamp := t.Format("2006/01/02 15:04:05")

	var fieldStr string
	if len(fields) > 0 {
		for k, v := range fields {
			if fieldStr != "" {
				fieldStr += " "
			}
			fieldStr += fmt.Sprintf("%s=%v", k, v)
		}
	}

	if fieldStr != "" {
		return fmt.Sprintf("%s [%s] [%s] %s  %s", timestamp, level.String(), l.component, msg, fieldStr)
	}
	return fmt.Sprintf("%s [%s] [%s] %s", timestamp, level.String(), l.component, msg)
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LevelDebug, msg, f)
}

// Info logs an info message
func (l *Logger) Info(msg string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LevelInfo, msg, f)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LevelWarn, msg, f)
}

// Error logs an error message
func (l *Logger) Error(msg string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LevelError, msg, f)
}

// WithComponent returns a new logger with the specified component name
func (l *Logger) WithComponent(component string) *Logger {
	return &Logger{
		level:       l.level,
		component:   component,
		file:        l.file, // Share file handle
		fileJSON:    l.fileJSON,
		writeToFile: l.writeToFile,
		writeStdout: l.writeStdout,
	}
}

// Package-level functions using the default logger

// Debug logs a debug message
func Debug(msg string, fields ...map[string]interface{}) {
	if defaultLogger != nil {
		defaultLogger.Debug(msg, fields...)
	}
}

// Info logs an info message
func Info(msg string, fields ...map[string]interface{}) {
	if defaultLogger != nil {
		defaultLogger.Info(msg, fields...)
	}
}

// Warn logs a warning message
func Warn(msg string, fields ...map[string]interface{}) {
	if defaultLogger != nil {
		defaultLogger.Warn(msg, fields...)
	}
}

// Error logs an error message
func Error(msg string, fields ...map[string]interface{}) {
	if defaultLogger != nil {
		defaultLogger.Error(msg, fields...)
	}
}

// Component returns a logger for a specific component
func Component(name string) *Logger {
	if defaultLogger != nil {
		return defaultLogger.WithComponent(name)
	}
	return nil
}

// GetProbeLogger returns the probe logger
func GetProbeLogger() *Logger {
	return probeLogger
}
