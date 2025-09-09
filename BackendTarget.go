package main

import (
	"net/url"
	"sync"
)

// Backend target avec load balancing simple
type BackendTarget struct {
	URLs    []*url.URL
	current int
	mu      sync.Mutex // Protection pour l'accès concurrent
}

// NewBackendTarget creates a new BackendTarget with proper initialization
func NewBackendTarget(urls []*url.URL) *BackendTarget {
	return &BackendTarget{
		URLs:    urls,
		current: 0,
		mu:      sync.Mutex{},
	}
}

// Round-robin simple pour sélectionner le prochain backend
func (bt *BackendTarget) NextURL() *url.URL {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	if len(bt.URLs) == 0 {
		return nil
	}

	// Capture de l'index actuel et mise à jour
	currentIndex := bt.current
	bt.current = (bt.current + 1) % len(bt.URLs)

	return bt.URLs[currentIndex]
}
