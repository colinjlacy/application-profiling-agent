// agent/cmd/agent/main.go
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type event struct {
	Pid uint64
	Sql [256]byte
}

func main() {
	bpfObj := getenv("BPF_OBJECT", "/pqexec.bpf.o")
	targetPattern := getenv("TARGET_PATTERN", "testapp")
	outputPath := getenv("OUTPUT_FILE", "/output/pqexec.log")

	log.Printf("[agent] using BPF object: %s", bpfObj)
	log.Printf("[agent] looking for process with cmdline containing: %q", targetPattern)

	pid, err := waitForPID(targetPattern)
	if err != nil {
		log.Fatalf("waitForPID: %v", err)
	}
	log.Printf("[agent] found target PID = %d", pid)

	libpqPath := fmt.Sprintf("/proc/%d/root/usr/lib/aarch64-linux-gnu/libpq.so.5", pid)

	ex, err := link.OpenExecutable(libpqPath)
	if err != nil {
		log.Fatalf("OpenExecutable(%s): %v", libpqPath, err)
	}

	// Load precompiled BPF object
	spec, err := ebpf.LoadCollectionSpec(bpfObj)
	if err != nil {
		log.Fatalf("LoadCollectionSpec(%s): %v", bpfObj, err)
	}

	var objs struct {
		TracePqexec *ebpf.Program `ebpf:"trace_pqexec"`
		Events      *ebpf.Map     `ebpf:"events"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("LoadAndAssign: %v", err)
	}
	defer objs.TracePqexec.Close()
	defer objs.Events.Close()

	// Attach uprobe to PQexec symbol in the executable (PLT stub)
	up, err := ex.Uprobe("PQexec", objs.TracePqexec, &link.UprobeOptions{
		PID: pid,
	})
	if err != nil {
		log.Fatalf("Uprobe(PQexec @ %s, pid=%d): %v", libpqPath, pid, err)
	}
	defer up.Close()

	// Ring buffer reader on the "events" map
	rb, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf.NewReader: %v", err)
	}
	defer rb.Close()

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", filepath.Dir(outputPath), err)
	}
	outf, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("open output file: %v", err)
	}
	defer outf.Close()

	log.Printf("[agent] attached to PQexec; logging to %s", outputPath)

	for {
		record, err := rb.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				log.Printf("[agent] ringbuf closed, exiting")
				return
			}
			log.Printf("ringbuf.Read: %v", err)
			continue
		}

		var ev event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("binary.Read: %v", err)
			continue
		}

		sql := cString(ev.Sql[:])
		line := fmt.Sprintf("ts=%s pid=%d sql=%s\n",
			time.Now().Format(time.RFC3339Nano), ev.Pid, sql)
		if _, err := outf.WriteString(line); err != nil {
			log.Printf("write output: %v", err)
		}
		// Also echo to stdout
		log.Print(strings.TrimRight(line, "\n"))
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// waitForPID finds the first PID whose cmdline contains pattern, polling until it appears.
func waitForPID(pattern string) (int, error) {
	for {
		pid := findPIDByCmdline(pattern)
		if pid != 0 {
			return pid, nil
		}
		time.Sleep(1 * time.Second)
	}
}

func findPIDByCmdline(pattern string) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdlinePath := filepath.Join("/proc", e.Name(), "cmdline")
		data, err := os.ReadFile(cmdlinePath)
		if err != nil {
			continue
		}
		// cmdline is NUL-separated argv
		cmd := strings.ReplaceAll(string(data), "\x00", " ")
		if strings.Contains(cmd, pattern) {
			return pid
		}
	}
	return 0
}

func cString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}
