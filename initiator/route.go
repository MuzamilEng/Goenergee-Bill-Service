package initiator

import (
	"github.com/gin-gonic/gin"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/glue/user"
	"go.uber.org/zap"
)

func InitRouting(
	grp *gin.RouterGroup,
	log zap.Logger,
	handler Handler,
) {
	user.Init(grp, log, handler.User)

}
