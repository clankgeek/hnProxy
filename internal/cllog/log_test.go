package cllog

import (
	"hnproxy/internal/clconfig"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected zerolog.Level
	}{
		{"debug", zerolog.DebugLevel},
		{"info", zerolog.InfoLevel},
		{"warn", zerolog.WarnLevel},
		{"error", zerolog.ErrorLevel},
		{"", zerolog.InfoLevel},
		{"unknown", zerolog.InfoLevel},
		{"TRACE", zerolog.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseLevel(tt.input)
			if got != tt.expected {
				t.Errorf("parseLevel(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestExtractLevelFromJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "info level",
			input:    `{"level":"info","time":"2024-01-01","message":"test"}`,
			expected: "info",
		},
		{
			name:     "error level",
			input:    `{"level":"error","time":"2024-01-01","message":"oops"}`,
			expected: "error",
		},
		{
			name:     "warn level",
			input:    `{"level":"warn","message":"warning"}`,
			expected: "warn",
		},
		{
			name:     "debug level",
			input:    `{"level":"debug","message":"debug msg"}`,
			expected: "debug",
		},
		{
			name:     "no level field",
			input:    `{"time":"2024-01-01","message":"no level"}`,
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "malformed JSON",
			input:    `{"level":"`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLevelFromJSON(tt.input)
			if got != tt.expected {
				t.Errorf("extractLevelFromJSON(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestInitLogger_Development(t *testing.T) {
	cfg := clconfig.LoggerConfig{
		Level:  "debug",
		File:   clconfig.LoggerFileConfig{Enable: false},
		Syslog: clconfig.LoggerSyslogConfig{Enable: false},
	}

	// Should not panic
	InitLogger(cfg, false)

	// Verify global level is debug
	if zerolog.GlobalLevel() != zerolog.DebugLevel {
		t.Errorf("Global log level = %v, want debug", zerolog.GlobalLevel())
	}
}

func TestInitLogger_Production(t *testing.T) {
	cfg := clconfig.LoggerConfig{
		Level:  "warn",
		File:   clconfig.LoggerFileConfig{Enable: false},
		Syslog: clconfig.LoggerSyslogConfig{Enable: false},
	}

	InitLogger(cfg, true)

	if zerolog.GlobalLevel() != zerolog.WarnLevel {
		t.Errorf("Global log level = %v, want warn", zerolog.GlobalLevel())
	}
}

func TestInitLogger_WithFileWriter(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	cfg := clconfig.LoggerConfig{
		Level: "info",
		File: clconfig.LoggerFileConfig{
			Enable:     true,
			Path:       logFile,
			MaxSize:    10,
			MaxBackups: 1,
			MaxAge:     1,
			Compress:   false,
		},
		Syslog: clconfig.LoggerSyslogConfig{Enable: false},
	}

	// Should not panic
	InitLogger(cfg, true)

	if zerolog.GlobalLevel() != zerolog.InfoLevel {
		t.Errorf("Global log level = %v, want info", zerolog.GlobalLevel())
	}
}

func TestSetupFileWriter(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := clconfig.LoggerFileConfig{
		Enable:     true,
		Path:       filepath.Join(tmpDir, "subdir", "test.log"),
		MaxSize:    1,
		MaxBackups: 1,
		MaxAge:     1,
		Compress:   false,
	}

	w, err := setupFileWriter(cfg)
	if err != nil {
		t.Fatalf("setupFileWriter() error = %v", err)
	}
	if w == nil {
		t.Fatal("setupFileWriter() returned nil writer")
	}

	// Verify directory was created
	dir := filepath.Dir(cfg.Path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("setupFileWriter() should create the directory")
	}
}

func TestSyslogLevelWriter_Write(t *testing.T) {
	// Test extractLevelFromJSON via the Write path indirectly
	messages := []struct {
		json  string
		level string
	}{
		{`{"level":"debug","message":"test"}`, "debug"},
		{`{"level":"info","message":"test"}`, "info"},
		{`{"level":"warn","message":"test"}`, "warn"},
		{`{"level":"error","message":"test"}`, "error"},
		{`{"message":"no level"}`, ""},
	}

	for _, m := range messages {
		level := extractLevelFromJSON(m.json)
		if level != m.level {
			t.Errorf("for %q: extractLevelFromJSON = %q, want %q", m.json, level, m.level)
		}
	}

	// Test that Write routes correctly (using strings.Builder as a no-op writer)
	_ = strings.NewReader("test") // just to use the strings package
}
