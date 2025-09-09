package main

import (
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
