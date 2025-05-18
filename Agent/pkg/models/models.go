package models

type Config struct {
	Monitor          *MonitorConfig     `yaml:"monitor"`
	ThreatIntel      *ThreatIntelConfig `yaml:"threat_intel"`
	RunningDirectory string
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
