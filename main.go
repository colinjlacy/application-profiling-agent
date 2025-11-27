// cmd/agent/main.go
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"gopkg.in/yaml.v3"

	"github.com/colinjlacy/application-profiling-agent/internal/hooks"
	"github.com/colinjlacy/application-profiling-agent/internal/model"
	"github.com/colinjlacy/application-profiling-agent/internal/proc"
)

type appState struct {
	HTTP      map[string]*model.HTTPCall
	DBQueries map[string]*model.DBQuery
	FSOps     map[string]*model.FSOp
	Sockets   map[string]*model.SocketConnect
}

func newAppState() *appState {
	return &appState{
		HTTP:      make(map[string]*model.HTTPCall),
		DBQueries: make(map[string]*model.DBQuery),
		FSOps:     make(map[string]*model.FSOp),
		Sockets:   make(map[string]*model.SocketConnect),
	}
}

func main() {
	outDir := getenvOr("OUT_DIR", "/out")

	spec, err := ebpf.LoadCollectionSpec("integration_bpf.o")
	if err != nil {
		log.Fatalf("loading BPF spec: %v", err)
	}

	objs := struct {
		Programs struct {
			KprobeConnect *ebpf.Program `ebpf:"kprobe_connect"`
			KprobeOpenat  *ebpf.Program `ebpf:"kprobe_openat"`
			UprobePQexec  *ebpf.Program `ebpf:"uprobe_PQexec"`
		}
		Maps struct {
			Events *ebpf.Map `ebpf:"events"`
		}
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Programs.KprobeConnect.Close()
	defer objs.Programs.KprobeOpenat.Close()
	defer objs.Programs.UprobePQexec.Close()
	defer objs.Maps.Events.Close()

	// Attach kprobes.
	var links []link.Link
	kc, err := link.Kprobe("connect", objs.Programs.KprobeConnect, nil)
	if err != nil {
		log.Fatalf("attach kprobe connect: %v", err)
	}
	links = append(links, kc)

	ko, err := link.Kprobe("openat", objs.Programs.KprobeOpenat, nil)
	if err != nil {
		log.Fatalf("attach kprobe openat: %v", err)
	}
	links = append(links, ko)

	// Attach uprobe for libpq PQexec.
	// You might need to resolve the actual path of libpq on your system.
	libpqPath := getenvOr("LIBPQ_PATH", "/usr/lib/x86_64-linux-gnu/libpq.so.5")
	up, err := link.Uprobe(libpqPath, "PQexec", objs.Programs.UprobePQexec, nil)
	if err != nil {
		log.Printf("warning: attach uprobe PQexec failed: %v", err)
	} else {
		links = append(links, up)
	}

	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	rd, err := ringbuf.NewReader(objs.Maps.Events)
	if err != nil {
		log.Fatalf("creating ringbuf reader: %v", err)
	}
	defer rd.Close()

	procResolver := proc.NewResolver()
	var mu sync.Mutex
	apps := make(map[string]*appState)

	// Periodic flush to files.
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			mu.Lock()
			for app, st := range apps {
				writeManifest(outDir, app, st)
			}
			mu.Unlock()
		}
	}()

	log.Printf("agent started, writing manifests to %s", outDir)

	// Handle shutdown signals.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

loop:
	for {
		select {
		case <-stop:
			log.Printf("shutting down")
			break loop
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				break
			}
			continue
		}

		if len(record.RawSample) < binary.Size(hooks.Event{}) {
			record.Done()
			continue
		}

		var ev hooks.Event
		if err := binary.Read(bytesReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			record.Done()
			continue
		}
		record.Done()

		appName := procResolver.AppName(int(ev.Pid))
		if appName == "" {
			continue // not opted-in
		}

		ts := ev.Timestamp()

		mu.Lock()
		st, ok := apps[appName]
		if !ok {
			st = newAppState()
			apps[appName] = st
		}

		switch ev.HookID {
		case hooks.HookOpenat:
			path := ev.Str1String()
			if path == "" {
				break
			}
			key := path
			fs, ok := st.FSOps[key]
			if !ok {
				fs = &model.FSOp{
					Path:      path,
					Flags:     int(ev.Num2),
					FirstSeen: ts,
					LastSeen:  ts,
					Count:     1,
				}
				st.FSOps[key] = fs
			} else {
				fs.LastSeen = ts
				fs.Count++
			}

		case hooks.HookPQExec:
			sql := ev.Str1String()
			if sql == "" {
				break
			}
			key := sql
			db, ok := st.DBQueries[key]
			if !ok {
				db = &model.DBQuery{
					DBType:    "postgres",
					Query:     sql,
					FirstSeen: ts,
					LastSeen:  ts,
					Count:     1,
				}
				st.DBQueries[key] = db
			} else {
				db.LastSeen = ts
				db.Count++
			}

		case hooks.HookConnect:
			// For now we only use port; IP parsing was minimal in C.
			port := uint16(ev.Num2 & 0xffff)
			key := fmt.Sprintf("port:%d", port)
			sock, ok := st.Sockets[key]
			if !ok {
				sock = &model.SocketConnect{
					Port:      port,
					FirstSeen: ts,
					LastSeen:  ts,
					Count:     1,
				}
				st.Sockets[key] = sock
			} else {
				sock.LastSeen = ts
				sock.Count++
			}
		}

		mu.Unlock()
	}

	// Final flush on exit.
	mu.Lock()
	for app, st := range apps {
		writeManifest(outDir, app, st)
	}
	mu.Unlock()
}

func writeManifest(outDir, app string, st *appState) {
	manifest := model.AppManifest{
		Application: app,
		GeneratedAt: time.Now(),
	}

	for _, q := range st.DBQueries {
		manifest.Databases = append(manifest.Databases, *q)
	}
	for _, fs := range st.FSOps {
		manifest.Filesystem = append(manifest.Filesystem, *fs)
	}
	for _, s := range st.Sockets {
		manifest.Sockets = append(manifest.Sockets, *s)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Printf("mkdir %s: %v", outDir, err)
		return
	}

	path := filepath.Join(outDir, fmt.Sprintf("%s.integrations.yaml", app))
	f, err := os.Create(path)
	if err != nil {
		log.Printf("create manifest %s: %v", path, err)
		return
	}
	defer f.Close()

	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	if err := enc.Encode(&manifest); err != nil {
		log.Printf("write manifest %s: %v", path, err)
		return
	}
	log.Printf("wrote manifest for app=%s to %s", app, path)
}

// bytesReader wraps a byte slice in a type that implements io.Reader,
// without allocations.
type bytesReader []byte

func (b bytesReader) Read(p []byte) (int, error) {
	n := copy(p, b)
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func getenvOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
