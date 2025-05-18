package agentEngine

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/bhaiFi/security-monitor/internal/agentScanner"
	"github.com/bhaiFi/security-monitor/internal/config"
	"github.com/bhaiFi/security-monitor/internal/logger"
	"github.com/bhaiFi/security-monitor/internal/scannerEngine"
	"github.com/bhaiFi/security-monitor/internal/signature"
	"github.com/bhaiFi/security-monitor/internal/threatintel"
	"github.com/bhaiFi/security-monitor/pkg/rpcEngine"
	"google.golang.org/grpc"
)

func (agentEngine *AgentEngine) Start() {
	logPrefix := "AgentEngine.Start"

	logger.LogInfo(logPrefix, "Starting agent engine", "", nil)

	executablePath, err := os.Executable()
	if err != nil {
		logger.LogError(logPrefix, "Failed to get executable path", "", err)
		log.Fatalf("Failed to get executable path: %v", err)
	}
	filePath := filepath.Dir(executablePath)
	logger.LogInfo(logPrefix, "Retrieved executable path", filePath, nil)

	cfg, err := config.LoadConfig(fmt.Sprintf("%v/configs/config.yaml", filePath))
	if err != nil {
		logger.LogError(logPrefix, "Failed to load configuration file", "", err)
		log.Fatalf("Failed to load config: %v", err)
	}
	cfg.RunningDirectory = filePath
	logger.LogInfo(logPrefix, "Loaded configuration successfully", "", nil)

	ti, err := threatintel.NewThreatIntel(cfg)
	if err != nil {
		logger.LogError(logPrefix, "Failed to initialize threat intelligence", "", err)
		log.Fatalf("Failed to initialize threat intel: %v", err)
	}
	logger.LogInfo(logPrefix, "Threat intelligence initialized", "", nil)

	sv, err := signature.NewVerifier()
	if err != nil {
		logger.LogError(logPrefix, "Failed to initialize signature verifier", "", err)
		log.Fatalf("Failed to initialize signature verifier: %v", err)
	}
	logger.LogInfo(logPrefix, "Signature verifier initialized", "", nil)

	scanner := agentScanner.NewScanner(cfg.Monitor, ti, sv)
	logger.LogInfo(logPrefix, "Scanner initialized", "", nil)

	ctx, cancel := context.WithCancel(context.Background())
	agentEngine.cancelFunc = cancel

	scanner.StartBackground(ctx)
	logger.LogInfo(logPrefix, "Started background scanner", "", nil)

	grpcServer := grpc.NewServer()
	agentEngine.grpcServer = grpcServer
	rpcEngine.RegisterServicesServer(grpcServer, scannerEngine.NewRPCServer(scanner))
	logger.LogInfo(logPrefix, "gRPC server initialized and services registered", "", nil)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%v", cfg.Monitor.GrpcPort))
	if err != nil {
		logger.LogError(logPrefix, "Failed to bind gRPC server", "", err)
		log.Fatalf("Failed to listen: %v", err)
	}
	logger.LogInfo(logPrefix, fmt.Sprintf("gRPC server listening on port %v", cfg.Monitor.GrpcPort), "", nil)

	if err := grpcServer.Serve(lis); err != nil {
		logger.LogError(logPrefix, "Failed to serve gRPC server", "", err)
		log.Fatalf("Failed to serve: %v", err)
	}
}

func (agentEngine *AgentEngine) Stop() {
	logPrefix := "AgentEngine.Stop"

	logger.LogInfo(logPrefix, "Stopping agent engine", "", nil)

	if agentEngine.cancelFunc != nil {
		agentEngine.cancelFunc()
		logger.LogInfo(logPrefix, "Cancelled background context", "", nil)
	}

	if agentEngine.grpcServer != nil {
		agentEngine.grpcServer.GracefulStop()
		logger.LogInfo(logPrefix, "gRPC server gracefully stopped", "", nil)
	}

	logger.LogInfo(logPrefix, "Agent engine stopped successfully", "", nil)
}
