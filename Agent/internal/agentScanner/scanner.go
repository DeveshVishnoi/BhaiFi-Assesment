package agentScanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bhaiFi/security-monitor/internal/logger"
	"github.com/bhaiFi/security-monitor/internal/signature"
	"github.com/bhaiFi/security-monitor/internal/threatintel"
	"github.com/bhaiFi/security-monitor/pkg/models"
	"github.com/shirou/gopsutil/v3/process"
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

type Scanner struct {
	config      *models.MonitorConfig
	threatIntel *threatintel.ThreatIntel
	sigVerifier *signature.Verifier

	unsignedCache      []ProcessInfo
	maliciousCache     []ProcessInfo
	relationshipsCache []RelationshipInfo

	mu sync.RWMutex
}

func NewScanner(cfg *models.MonitorConfig, ti *threatintel.ThreatIntel, sv *signature.Verifier) *Scanner {
	return &Scanner{
		config:      cfg,
		threatIntel: ti,
		sigVerifier: sv,
	}
}

func (s *Scanner) startScanning(ctx context.Context) {
	logPrefix := "agentScanner.startScanning"

	s.scanAll() // initial scan

	ticker := time.NewTicker(time.Duration(models.TimeInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.scanAll()
		case <-ctx.Done():
			logger.LogInfo(logPrefix, "Scanner shutting down", "", nil)
			return
		}
	}
}

func (s *Scanner) StartBackground(ctx context.Context) {
	go s.startScanning(ctx)
}

func (s *Scanner) scanAll() {
	logPrefix := "agentScanner.scanAll"

	processes, err := process.Processes()
	if err != nil {
		logger.LogError(logPrefix, "Failed to get process list", "", err)
		return
	}

	logger.LogInfo(logPrefix, fmt.Sprintf("Length of the Processes - %d", len(processes)), "", nil)

	var unsigned []ProcessInfo
	var malicious []ProcessInfo
	var relationships []RelationshipInfo

	unsignedSeen := make(map[string]bool)
	maliciousMap := make(map[string]bool)

	for _, p := range processes {
		pid := p.Pid

		name, err := p.Name()
		if err != nil {
			logger.LogError(logPrefix, "Failed to get process name", fmt.Sprintf("PID: %d", pid), err)
			continue
		}

		exe, err := p.Exe()
		if err != nil {
			logger.LogError(logPrefix, "Failed to get executable path", fmt.Sprintf("PID: %d", pid), err)
			continue
		}

		if exe == "" {
			continue
		}

		if isSigned, err := s.sigVerifier.Verify(exe); err == nil && !isSigned {
			if _, exists := unsignedSeen[exe]; !exists {
				unsignedSeen[exe] = true
				unsigned = append(unsigned, ProcessInfo{
					PID:     pid,
					Name:    name,
					ExePath: exe,
				})
			}
		} else if err != nil {
			logger.LogError(logPrefix, "Signature verification failed", exe, err)
		}

		if exe != "" && s.threatIntel.IsMalicious(exe) {
			if _, exist := maliciousMap[exe]; !exist {
				maliciousMap[exe] = true
				malicious = append(malicious, ProcessInfo{
					PID:     pid,
					Name:    name,
					ExePath: exe,
				})
			}
		}

		if parent, err := p.Parent(); err == nil && parent != nil {
			parentName, err := parent.Name()
			if err != nil {
				logger.LogError(logPrefix, "Failed to get parent process name", fmt.Sprintf("Parent PID: %d", parent.Pid), err)
				continue
			}

			relationships = append(relationships, RelationshipInfo{
				ParentPID:  parent.Pid,
				ParentName: parentName,
				ChildPID:   pid,
				ChildName:  name,
			})

			if isSuspiciousParent(parentName) && isSuspiciousChild(name) {
				logger.LogInfo(logPrefix, fmt.Sprintf("[Suspicious] Parent: %s (%d) -> Child: %s (%d)", parentName, parent.Pid, name, pid), "", nil)
			}
		}
	}

	s.mu.Lock()
	s.unsignedCache = unsigned
	s.maliciousCache = malicious
	s.relationshipsCache = relationships
	s.mu.Unlock()
}

func (s *Scanner) GetUnsignedProcesses() []ProcessInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unsignedCache
}

func (s *Scanner) GetMaliciousProcesses() []ProcessInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maliciousCache
}

func (s *Scanner) GetSuspiciousRelationships() []RelationshipInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.relationshipsCache
}

func isSuspiciousParent(name string) bool {
	suspiciousParents := map[string]bool{
		"winword.exe":  true,
		"excel.exe":    true,
		"powerpnt.exe": true,
		"outlook.exe":  true,
	}
	return suspiciousParents[name]
}

func isSuspiciousChild(name string) bool {
	suspiciousChildren := map[string]bool{
		"powershell.exe": true,
		"cmd.exe":        true,
		"wscript.exe":    true,
		"cscript.exe":    true,
		"mshta.exe":      true,
	}
	return suspiciousChildren[name]
}
