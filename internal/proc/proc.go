// internal/proc/proc.go
package proc

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Resolver struct {
	mu    sync.Mutex
	cache map[int]string
}

func NewResolver() *Resolver {
	return &Resolver{cache: make(map[int]string)}
}

// AppName returns the application name for a PID, based on CODEINT_SERVICE.
// Empty string means "unknown"/"not opted-in".
func (r *Resolver) AppName(pid int) string {
	r.mu.Lock()
	if name, ok := r.cache[pid]; ok {
		r.mu.Unlock()
		return name
	}
	r.mu.Unlock()

	environPath := filepath.Join("/proc", fmt.Sprint(pid), "environ")
	data, err := os.ReadFile(environPath)
	if err != nil {
		r.mu.Lock()
		r.cache[pid] = ""
		r.mu.Unlock()
		return ""
	}

	parts := bytes.Split(data, []byte{0})
	var app string
	for _, kv := range parts {
		if len(kv) == 0 {
			continue
		}
		if !bytes.HasPrefix(kv, []byte("CODEINT_SERVICE=")) {
			continue
		}
		app = strings.TrimPrefix(string(kv), "CODEINT_SERVICE=")
		break
	}

	r.mu.Lock()
	r.cache[pid] = app
	r.mu.Unlock()
	return app
}
