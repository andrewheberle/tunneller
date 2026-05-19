package tracker

import "sync"

type CookieTracker struct {
	mu      sync.RWMutex
	cookies map[string]map[string]any
}

func NewCookieTracker() *CookieTracker {
	return &CookieTracker{cookies: make(map[string]map[string]any)}
}

func (tracker *CookieTracker) Record(key, cookie string) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if tracker.cookies[key] == nil {
		tracker.cookies[key] = make(map[string]any)
	}

	tracker.cookies[key][cookie] = ""
}

func (tracker *CookieTracker) Found(key, cookie string) bool {
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	_, found := tracker.cookies[key][cookie]

	return found
}
