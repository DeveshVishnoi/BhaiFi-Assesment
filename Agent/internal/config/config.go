package config

import (
	"os"

	"github.com/bhaiFi/security-monitor/internal/logger"
	"github.com/bhaiFi/security-monitor/pkg/models"
	"gopkg.in/yaml.v2"
)

func LoadConfig(path string) (*models.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		logger.LogError("LoadConfig", "unable to read the file", "", err)
		return nil, err
	}

	var cfg models.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		logger.LogError("LoadConfig", "error getting the marshal the yaml data", "", err)
		return nil, err
	}

	return &cfg, nil
}
