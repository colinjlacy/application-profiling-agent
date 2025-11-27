// internal/model/manifest.go
package model

import "time"

type HTTPCall struct {
	Direction  string    `yaml:"direction"` // "outbound" (for now)
	Method     string    `yaml:"method,omitempty"`
	URL        string    `yaml:"url,omitempty"`
	SampleBody string    `yaml:"sample_body,omitempty"`
	FirstSeen  time.Time `yaml:"first_seen"`
	LastSeen   time.Time `yaml:"last_seen"`
	Count      int       `yaml:"count"`
}

type DBQuery struct {
	DBType    string    `yaml:"db_type"` // e.g. "postgres"
	Query     string    `yaml:"query"`
	FirstSeen time.Time `yaml:"first_seen"`
	LastSeen  time.Time `yaml:"last_seen"`
	Count     int       `yaml:"count"`
}

type FSOp struct {
	Path      string    `yaml:"path"`
	Flags     int       `yaml:"flags"`
	FirstSeen time.Time `yaml:"first_seen"`
	LastSeen  time.Time `yaml:"last_seen"`
	Count     int       `yaml:"count"`
}

type SocketConnect struct {
	IP        string    `yaml:"ip,omitempty"`
	Port      uint16    `yaml:"port,omitempty"`
	FirstSeen time.Time `yaml:"first_seen"`
	LastSeen  time.Time `yaml:"last_seen"`
	Count     int       `yaml:"count"`
}

type AppManifest struct {
	Application string          `yaml:"application"`
	GeneratedAt time.Time       `yaml:"generated_at"`
	HTTP        []HTTPCall      `yaml:"http,omitempty"`
	Databases   []DBQuery       `yaml:"databases,omitempty"`
	Filesystem  []FSOp          `yaml:"filesystem,omitempty"`
	Sockets     []SocketConnect `yaml:"sockets,omitempty"`
}
