package auth

import (
	"os"
	"time"

	"github.com/AdRoll/goamz/aws"
	"github.com/AdRoll/goamz/dynamodb"
)

// getDynamoDBTable returns DynamoDB table by name and hash key.
func getDynamoDBTable(tableName, hashKeyAttributeName string) *dynamodb.Table {
	// Get AWS credentials from environment variables.
	key := os.Getenv("AWS_ACCESS_KEY_ID")
	secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	auth, err := aws.GetAuth(key, secret, "", time.Time{})
	if err != nil {
		return nil
	}

	// Get DynamoDB server.
	server := dynamodb.Server{
		Auth:        auth,
		Region:      aws.APNortheast,
		RetryPolicy: aws.DynamoDBRetryPolicy{},
	}

	// Prepare primary key for retrieve table.
	pk := dynamodb.PrimaryKey{}
	pk.KeyAttribute = dynamodb.NewStringAttribute(hashKeyAttributeName, "")

	return server.NewTable(tableName, pk)
}
