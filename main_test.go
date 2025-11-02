package main

import (
	"flag"
	"os"
	"testing"
)

func TestParseCommandLineArgs(t *testing.T) {
	// Save original args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	tests := []struct {
		name        string
		args        []string
		wantConfig  string
		wantExample bool
		wantVersion bool
		wantErr     bool
	}{
		{
			name:        "Valid config file",
			args:        []string{"prog", "-config", "test.yaml"},
			wantConfig:  "test.yaml",
			wantExample: false,
			wantVersion: false,
			wantErr:     false,
		},
		{
			name:        "Example flag",
			args:        []string{"prog", "-example"},
			wantConfig:  "",
			wantExample: true,
			wantVersion: false,
			wantErr:     false,
		},
		{
			name:        "Version flag",
			args:        []string{"prog", "-version"},
			wantConfig:  "",
			wantExample: false,
			wantVersion: true,
			wantErr:     false,
		},
		{
			name:        "No arguments",
			args:        []string{"prog"},
			wantConfig:  "",
			wantExample: false,
			wantVersion: false,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset flag parsing
			flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
			os.Args = tt.args

			gotConfig, gotExample, gotVersion, err := parseCommandLineArgs()

			if tt.wantVersion && tt.wantVersion != gotVersion {
				t.Errorf("parseCommandLineArgs() version = %v, want %v", gotVersion, tt.wantVersion)
				return
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("parseCommandLineArgs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if gotConfig != tt.wantConfig {
				t.Errorf("parseCommandLineArgs() config = %v, want %v", gotConfig, tt.wantConfig)
			}

			if gotExample != tt.wantExample {
				t.Errorf("parseCommandLineArgs() example = %v, want %v", gotExample, tt.wantExample)
			}
		})
	}
}
