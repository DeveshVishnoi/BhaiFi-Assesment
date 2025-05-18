package agentEngine

import (
	"context"

	"google.golang.org/grpc"
)

type AgentEngine struct {
	cancelFunc context.CancelFunc
	grpcServer *grpc.Server
}
