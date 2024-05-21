package initiator

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

// MongoInitiator is a struct that implements the Initiator interface for MongoDB connections.

func InitDB(url string, logger *zap.Logger) *mongo.Client {
	ctx := context.Background()
	client, err := mongo.NewClient(options.Client().ApplyURI(url))
	if err != nil {
		logger.Fatal("failed create new mongo db instance", zap.Error(err))
	}
	err = client.Connect(ctx)
	if err != nil {
		logger.Fatal("unable to connect to mongodb  server", zap.Error(err))
	}

	//ping the database
	err = client.Ping(ctx, nil)
	if err != nil {
		logger.Fatal("unable to connect db")
	}
	fmt.Println("Connected to MongoDB")
	return client
}

// getting database collections
