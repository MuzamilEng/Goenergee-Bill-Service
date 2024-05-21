package persistancedb

import (
	"github.com/spf13/viper"
	"go.mongodb.org/mongo-driver/mongo"
)

func GetCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	collection := client.Database(viper.GetString("db_name")).Collection(collectionName)
	return collection
}
