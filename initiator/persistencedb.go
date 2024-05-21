package initiator

import (
	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants/model/persistancedb"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/storage/persistence"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/storage/persistence/goenergy"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

type Persistence struct {
	User persistence.User
}

func InitPersistence(db *mongo.Client, log zap.Logger) Persistence {
	return Persistence{
		User: goenergy.Init(persistancedb.GetCollection(db, "transactions"), persistancedb.GetCollection(db, "auth"), persistancedb.GetCollection(db, "users"), persistancedb.GetCollection(db, "commission_config"), log),
	}
}
