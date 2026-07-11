package clbackend

import (
	"fmt"
	"net/url"
	"sync"
	"testing"
)

func TestBackendTarget_NextURL(t *testing.T) {
	tests := []struct {
		name     string
		urls     []string
		expected []string
	}{
		{
			name:     "Single backend",
			urls:     []string{"http://localhost:3001"},
			expected: []string{"http://localhost:3001", "http://localhost:3001"},
		},
		{
			name:     "Multiple backends round-robin",
			urls:     []string{"http://localhost:3001", "http://localhost:3002", "http://localhost:3003"},
			expected: []string{"http://localhost:3001", "http://localhost:3002", "http://localhost:3003", "http://localhost:3001"},
		},
		{
			name:     "Empty backends",
			urls:     []string{},
			expected: []string{"", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := &BackendTarget{
				URLs: make([]*url.URL, 0, len(tt.urls)),
			}

			// Parse URLs
			for _, u := range tt.urls {
				parsed, err := url.Parse(u)
				if err != nil {
					t.Fatalf("Failed to parse URL %s: %v", u, err)
				}
				target.URLs = append(target.URLs, parsed)
			}

			// Test round-robin
			for i, expected := range tt.expected {
				got := target.NextURL()
				var gotStr string
				if got != nil {
					gotStr = got.String()
				}

				if gotStr != expected {
					t.Errorf("NextURL() call %d = %v, want %v", i+1, gotStr, expected)
				}
			}
		})
	}
}

func TestServer_BackendTarget(t *testing.T) {
	tests := []struct {
		name     string
		urls     []string
		expected []string
	}{
		{
			name:     "Single backend",
			urls:     []string{"http://localhost:3001"},
			expected: []string{"http://localhost:3001", "http://localhost:3001"},
		},
		{
			name:     "Multiple backends round-robin",
			urls:     []string{"http://localhost:3001", "http://localhost:3002", "http://localhost:3003"},
			expected: []string{"http://localhost:3001", "http://localhost:3002", "http://localhost:3003", "http://localhost:3001"},
		},
		{
			name:     "Empty backends",
			urls:     []string{},
			expected: []string{"", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := &BackendTarget{
				URLs: make([]*url.URL, 0, len(tt.urls)),
			}

			// Parse URLs
			for _, u := range tt.urls {
				parsed, err := url.Parse(u)
				if err != nil {
					t.Fatalf("Failed to parse URL %s: %v", u, err)
				}
				target.URLs = append(target.URLs, parsed)
			}

			// Test round-robin
			for i, expected := range tt.expected {
				got := target.NextURL()
				var gotStr string
				if got != nil {
					gotStr = got.String()
				}

				if gotStr != expected {
					t.Errorf("NextURL() call %d = %v, want %v", i+1, gotStr, expected)
				}
			}
		})
	}
}

func TestBackendTarget_Concurrent(t *testing.T) {
	target := &BackendTarget{
		URLs: []*url.URL{
			mustParseURL("http://localhost:3001"),
			mustParseURL("http://localhost:3002"),
		},
	}

	// Test plus simple et direct
	const numGoroutines = 10
	const requestsPerGoroutine = 100

	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make(map[string]int)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localResults := make(map[string]int)

			for j := 0; j < requestsPerGoroutine; j++ {
				url := target.NextURL()
				if url != nil {
					localResults[url.String()]++
				}
			}

			// Merge results thread-safely
			mu.Lock()
			for url, count := range localResults {
				results[url] += count
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	// Verify results
	totalRequests := 0
	for url, count := range results {
		totalRequests += count
		if url != "http://localhost:3001" && url != "http://localhost:3002" {
			t.Errorf("Unexpected URL: %s", url)
		}
	}

	expectedTotal := numGoroutines * requestsPerGoroutine
	if totalRequests != expectedTotal {
		t.Errorf("Got %d total requests, want %d", totalRequests, expectedTotal)
	}

	t.Logf("✅ Concurrent test passed: %d total requests", totalRequests)
	for url, count := range results {
		percentage := float64(count) / float64(totalRequests) * 100
		t.Logf("📊 %s: %d requests (%.1f%%)", url, count, percentage)
	}
}

// Benchmark tests
func BenchmarkBackendTarget_NextURL(b *testing.B) {
	target := &BackendTarget{
		URLs: []*url.URL{
			mustParseURL("http://localhost:3001"),
			mustParseURL("http://localhost:3002"),
			mustParseURL("http://localhost:3003"),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		target.NextURL()
	}
}

// Helper function for tests
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(fmt.Sprintf("URL invalide: %s", rawURL))
	}
	return u
}

func TestNewBackendTarget(t *testing.T) {
	urls := []*url.URL{
		mustParseURL("http://localhost:3001"),
		mustParseURL("http://localhost:3002"),
	}

	bt := NewBackendTarget(urls)

	if bt == nil {
		t.Fatal("NewBackendTarget returned nil")
	}
	if bt.current != 0 {
		t.Errorf("current = %d, want 0", bt.current)
	}
	if len(bt.URLs) != 2 {
		t.Errorf("len(URLs) = %d, want 2", len(bt.URLs))
	}

	// Verify round-robin starts from index 0
	first := bt.NextURL()
	if first.String() != "http://localhost:3001" {
		t.Errorf("first URL = %s, want http://localhost:3001", first.String())
	}
}

func TestNewBackendTarget_Empty(t *testing.T) {
	bt := NewBackendTarget([]*url.URL{})
	if bt == nil {
		t.Fatal("NewBackendTarget returned nil")
	}
	if bt.NextURL() != nil {
		t.Error("NextURL on empty target should return nil")
	}
}

func TestMustParseURL_Valid(t *testing.T) {
	u := MustParseURL("http://localhost:8080/path?q=1")
	if u == nil {
		t.Fatal("MustParseURL returned nil for valid URL")
	}
	if u.Host != "localhost:8080" {
		t.Errorf("Host = %s, want localhost:8080", u.Host)
	}
	if u.Path != "/path" {
		t.Errorf("Path = %s, want /path", u.Path)
	}
}

func TestMustParseURL_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustParseURL should panic on invalid URL")
		}
	}()
	// This URL has an invalid scheme that causes url.Parse to return an error
	MustParseURL("://invalid")
}
