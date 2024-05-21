package utils

import (
	"context"

	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants/errors"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants/model/dto"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

func IsDataExist(ctx context.Context, filter bson.M, log *zap.Logger, collection *mongo.Collection) bool {
	var usr dto.User
	err := collection.FindOne(ctx, filter).Decode(&usr)
	if err == mongo.ErrNoDocuments {
		return false
	} else if err != nil {
		err = errors.ErrInvalidUserInput.Wrap(err, "unable to get data", zap.Any("data", filter))
		log.Error("unable to check data existance", zap.Error(err))
		return true // return true as default for unknown issues
	}

	return true

}
