// internal/hooks/hooks.go
package hooks

import "time"

const (
	HookConnect = 1
	HookOpenat  = 2
	HookPQExec  = 3
)

// Event mirrors the C struct `struct event` layout.
// Make sure field order and sizes match.
type Event struct {
	TsNs   uint64
	Pid    uint32
	Tid    uint32
	HookID uint32

	Num1 uint64
	Num2 uint64

	Str1 [128]byte
	Str2 [256]byte
}

func (e *Event) Timestamp() time.Time {
	return time.Unix(0, int64(e.TsNs))
}

func (e *Event) Str1String() string {
	n := 0
	for ; n < len(e.Str1); n++ {
		if e.Str1[n] == 0 {
			break
		}
	}
	return string(e.Str1[:n])
}

func (e *Event) Str2String() string {
	n := 0
	for ; n < len(e.Str2); n++ {
		if e.Str2[n] == 0 {
			break
		}
	}
	return string(e.Str2[:n])
}
