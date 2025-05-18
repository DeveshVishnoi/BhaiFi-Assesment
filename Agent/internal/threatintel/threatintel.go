package threatintel

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/bhaiFi/security-monitor/internal/logger"
	"github.com/bhaiFi/security-monitor/pkg/models"
)

const logPrefix = "threatintel"

type ThreatIntel struct {
	config          *models.ThreatIntelConfig
	maliciousHashes map[string]bool
	mu              sync.RWMutex
}

func NewThreatIntel(cfg *models.Config) (*ThreatIntel, error) {
	logger.LogInfo(logPrefix, "Initializing ThreatIntel", "", nil)

	ti := &ThreatIntel{
		config:          cfg.ThreatIntel,
		maliciousHashes: make(map[string]bool),
	}

	if err := ti.loadThreatData(cfg.RunningDirectory); err != nil {
		logger.LogError(logPrefix, "Failed to load threat data", "", err)
		return nil, fmt.Errorf("failed to load threat data: %w", err)
	}

	logger.LogInfo(logPrefix, "ThreatIntel initialized successfully", "", nil)
	return ti, nil
}

func (ti *ThreatIntel) loadThreatData(directory string) error {
	logger.LogInfo(logPrefix, "Loading threat data", fmt.Sprintf("directory: %s", directory), nil)

	ti.mu.Lock()
	defer ti.mu.Unlock()

	for _, feed := range ti.config.Feeds {
		switch feed.Format {
		case "json":
			path := fmt.Sprintf("%v/data/malware_hashes.json", directory)
			logger.LogInfo(logPrefix, "Loading JSON feed", path, nil)
			if err := ti.loadJSONFeed(path); err != nil {
				logger.LogError(logPrefix, "Failed to load JSON feed", path, err)
				return fmt.Errorf("failed to load JSON feed: %w", err)
			}
		case "csv":
			logger.LogInfo(logPrefix, "Loading CSV feed", feed.Path, nil)
			if err := ti.loadCSVFeed(feed.Path); err != nil {
				logger.LogError(logPrefix, "Failed to load CSV feed", feed.Path, err)
				return fmt.Errorf("failed to load CSV feed: %w", err)
			}
		default:
			err := fmt.Errorf("unsupported feed format: %s", feed.Format)
			logger.LogError(logPrefix, "Unsupported feed format", feed.Format, err)
			return err
		}
	}

	return nil
}

func (ti *ThreatIntel) loadJSONFeed(path string) error {
	file, err := os.Open(path)
	if err != nil {
		logger.LogError(logPrefix, "Failed to open JSON file", path, err)
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		logger.LogError(logPrefix, "Failed to read JSON file", path, err)
		return fmt.Errorf("failed to read file: %w", err)
	}

	var hashes []models.MaliciousHash
	if err := json.Unmarshal(data, &hashes); err != nil {
		logger.LogError(logPrefix, "Failed to unmarshal JSON", path, err)
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	for _, h := range hashes {
		if h.MD5 != "" {
			ti.maliciousHashes[h.MD5] = true
		}
		if h.SHA256 != "" {
			ti.maliciousHashes[h.SHA256] = true
		}
	}

	logger.LogInfo(logPrefix, "Loaded JSON feed successfully", path, nil)
	return nil
}

func (ti *ThreatIntel) loadCSVFeed(path string) error {
	file, err := os.Open(path)
	if err != nil {
		logger.LogError(logPrefix, "Failed to open CSV file", path, err)
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		logger.LogError(logPrefix, "Failed to read CSV file", path, err)
		return fmt.Errorf("failed to read CSV: %w", err)
	}

	startIdx := 0
	if len(records) > 0 && (records[0][0] == "md5" || records[0][0] == "sha256") {
		startIdx = 1
	}

	for i := startIdx; i < len(records); i++ {
		record := records[i]
		if len(record) >= 1 {
			hash := record[0]
			if len(hash) == 32 || len(hash) == 64 {
				ti.maliciousHashes[hash] = true
			}
		}
	}

	logger.LogInfo(logPrefix, "Loaded CSV feed successfully", path, nil)
	return nil
}

func (ti *ThreatIntel) IsMalicious(filePath string) bool {
	md5Hash, sha256Hash, err := calculateFileHashes(filePath)
	if err != nil {
		logger.LogError(logPrefix, "Failed to calculate file hashes", filePath, err)
		return false
	}

	ti.mu.RLock()
	defer ti.mu.RUnlock()

	if ti.maliciousHashes[md5Hash] || ti.maliciousHashes[sha256Hash] {
		logger.LogInfo(logPrefix, "Malicious file detected", filePath, nil)
		return true
	}

	logger.LogInfo(logPrefix, "File is clean", filePath, nil)
	return false
}

func calculateFileHashes(filePath string) (string, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		logger.LogError(logPrefix, "Failed to open file for hash calculation", filePath, err)
		return "", "", err
	}
	defer file.Close()

	md5Hasher := md5.New()
	sha256Hasher := sha256.New()
	multiWriter := io.MultiWriter(md5Hasher, sha256Hasher)

	if _, err := io.Copy(multiWriter, file); err != nil {
		logger.LogError(logPrefix, "Failed to read file for hashing", filePath, err)
		return "", "", err
	}

	md5Hash := hex.EncodeToString(md5Hasher.Sum(nil))
	sha256Hash := hex.EncodeToString(sha256Hasher.Sum(nil))

	return md5Hash, sha256Hash, nil
}
