package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"api_invoker/rpcEngine"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func main() {
	r := gin.Default()
	r.GET("/api/scan/:message", scanHandler)
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to run Gin server: %v", err)
	}
}

func scanHandler(c *gin.Context) {
	messageType := c.Param("message")

	// Set up a context with timeout to avoid indefinite hang
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to connect to gRPC server", "details": err.Error()})
		return
	}
	defer conn.Close()

	client := rpcEngine.NewServicesClient(conn)
	stream, err := client.Messaging(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create gRPC stream", "details": err.Error()})
		return
	}

	// Send request message
	if err := stream.Send(&rpcEngine.Message{
		Message:     []byte("request"),
		MessageType: messageType,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send message", "details": err.Error()})
		return
	}

	var results []interface{}

	// Loop to receive all messages
	for {
		resp, err := stream.Recv()
		if err != nil {
			// Check if the stream is closed normally
			if status.Code(err) == codes.Canceled || status.Code(err) == codes.DeadlineExceeded {
				break
			}
			break // You may log or handle differently for other errors
		}

		switch resp.MessageType {
		case "unsignedResults", "maliciousResults":
			var processes []ProcessInfo
			if err := json.Unmarshal(resp.Message, &processes); err != nil {
				continue
			}
			for _, proc := range processes {
				results = append(results, gin.H{
					"PID":     proc.PID,
					"Name":    proc.Name,
					"ExePath": proc.ExePath,
				})
			}

		case "relationshipResults":
			var rels []RelationshipInfo
			if err := json.Unmarshal(resp.Message, &rels); err != nil {
				continue
			}
			for _, r := range rels {
				results = append(results, gin.H{
					"ParentName": r.ParentName,
					"ParentPID":  r.ParentPID,
					"ChildName":  r.ChildName,
					"ChildPID":   r.ChildPID,
				})
			}

		default:
			// Fallback for any other message type
			results = append(results, gin.H{
				"RawMessage": string(resp.Message),
			})
		}
	}

	c.JSON(http.StatusOK, results)
}
