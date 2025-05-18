package main

import (
	"crypto/x509"
	"sync"
)

type ProcessInfo struct {
	PID     int32   `json:"pid"`
	Name    string  `json:"name"`
	ExePath string  `json:"exePath"`
	Signer  *string `json:"signer,omitempty"`
}

type RelationshipInfo struct {
	ParentPID  int32  `json:"parentPid"`
	ParentName string `json:"parentName"`
	ChildPID   int32  `json:"childPid"`
	ChildName  string `json:"childName"`
}

type MonitorConfig struct {
	IntervalSeconds int      `yaml:"interval_seconds"`
	SensitiveDirs   []string `yaml:"sensitive_dirs"`
	GrpcPort        string   `yaml:"grpc_port"`
}

type ThreatIntelConfig struct {
	Feeds []ThreatFeed `yaml:"feeds"`
}

type ThreatFeed struct {
	Path   string `yaml:"path"`
	Format string `yaml:"format"`
}

type MaliciousHash struct {
	MD5    string `json:"md5"`
	SHA256 string `json:"sha256"`
	Type   string `json:"type"`
}
type ThreatIntel struct {
	config          *ThreatIntelConfig
	maliciousHashes map[string]bool
	mu              sync.RWMutex
}
type Verifier struct {
	trustedRoots *x509.CertPool
}
type Scanner struct {
	config      *MonitorConfig
	threatIntel *ThreatIntel
	sigVerifier *Verifier

	unsignedCache      []ProcessInfo
	maliciousCache     []ProcessInfo
	relationshipsCache []RelationshipInfo

	mu sync.RWMutex
}
