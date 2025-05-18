package scannerEngine

import (
	"encoding/json"

	"github.com/bhaiFi/security-monitor/internal/agentScanner"
	"github.com/bhaiFi/security-monitor/internal/logger"
	"github.com/bhaiFi/security-monitor/pkg/rpcEngine"
)

const logPrefix = "ScannerEngine"

type RPCServer struct {
	rpcEngine.UnimplementedServicesServer
	scanner *agentScanner.Scanner
}

func NewRPCServer(scanner *agentScanner.Scanner) *RPCServer {
	logger.LogInfo(logPrefix, "Initializing RPC server", "", nil)
	return &RPCServer{
		scanner: scanner,
	}
}

func (s *RPCServer) Messaging(stream rpcEngine.Services_MessagingServer) error {
	for {
		// Receive message from client
		msg, err := stream.Recv()
		if err != nil {
			logger.LogError(logPrefix, "Error receiving message from client", "", err)
			return err
		}
		logger.LogInfo(logPrefix, "Received message type", msg.MessageType, nil)

		// Process based on message type
		var response []byte
		var responseType string

		switch msg.MessageType {
		case "checkUnsigned":
			unsignedProcs := s.scanner.GetUnsignedProcesses()
			response, err = json.Marshal(unsignedProcs)
			if err != nil {
				logger.LogError(logPrefix, "Failed to marshal unsigned processes", "", err)
				response = []byte("error marshaling unsigned processes")
				responseType = "error"
			} else {
				responseType = "unsignedResults"
			}

		case "checkMalicious":
			maliciousProcs := s.scanner.GetMaliciousProcesses()
			response, err = json.Marshal(maliciousProcs)
			if err != nil {
				logger.LogError(logPrefix, "Failed to marshal malicious processes", "", err)
				response = []byte("error marshaling malicious processes")
				responseType = "error"
			} else {
				responseType = "maliciousResults"
			}

		case "checkRelationships":
			suspiciousRels := s.scanner.GetSuspiciousRelationships()
			response, err = json.Marshal(suspiciousRels)
			if err != nil {
				logger.LogError(logPrefix, "Failed to marshal suspicious relationships", "", err)
				response = []byte("error marshaling suspicious relationships")
				responseType = "error"
			} else {
				responseType = "relationshipResults"
			}

		default:
			logger.LogError(logPrefix, "Unknown message type received", msg.MessageType, nil)
			response = []byte("unknown request type")
			responseType = "error"
		}

		// Send response back to client
		if err := stream.Send(&rpcEngine.Message{
			Message:     response,
			MessageType: responseType,
		}); err != nil {
			logger.LogError(logPrefix, "Failed to send response", "", err)
			return err
		}

		logger.LogInfo(logPrefix, "Response sent successfully", responseType, nil)
	}
}
