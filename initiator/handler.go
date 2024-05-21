package initiator

import (
	"github.com/paymax2022/Goenergee-Bill-Service/internal/handler"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/handler/goenergy"
	"go.uber.org/zap"
)

type Handler struct {
	User handler.User
}

func InitHandler(module Module, log zap.Logger) Handler {
	return Handler{
		User: goenergy.Init(module.User, log),
	}
}
