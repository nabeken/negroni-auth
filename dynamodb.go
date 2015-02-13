package auth

import (
	"os"
	"time"

	"github.com/AdRoll/goamz/aws"
	"github.com/AdRoll/goamz/dynamodb"
)

// DynamoDBBasic is a DataStore store userid, hashed password pairs on DynamoDB.
type dynamoDBBasic struct {
	table                 *dynamodb.Table
	passwordAttributeName string
}

// NewDynamoDBBasic returns dynamoDBBasic builded from:
// - DynamoDB table name (tableName)
// - Attribute name that store userid (userIdAttributeName)
// - Attribute name that store password (passwordAttributeName)
func NewDynamoDBBasic(tableName, userIdAttributeName, passwordAttributeName string) (*dynamoDBBasic, error) {
	return &dynamoDBBasic{
		table: getDynamoDBTable(tableName, userIdAttributeName),
		passwordAttributeName: passwordAttributeName,
	}, nil
}

// dynamoDBBasic.Get return hashed password by userid.
func (d *dynamoDBBasic) Get(userId string) (hashedPassword []byte, found bool) {
	// Retrieve user credentials (userid, hashed password) from database by userid.
	key := &dynamodb.Key{HashKey: userId}
	userCred, err := d.table.GetItem(key)
	// If there is no user has this userid. Fail.
	if err != nil {
		return nil, false
	}
	// Extract hashed password from credentials.
	hashedPassword = []byte(userCred[d.passwordAttributeName].Value)

	return hashedPassword, true
}

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
