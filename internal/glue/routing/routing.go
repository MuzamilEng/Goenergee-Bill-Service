package routing

import (
	"fmt"
	"net/url"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type Route struct {
	Method     string
	Path       string
	Handler    gin.HandlerFunc
	Middleware []gin.HandlerFunc
	Domains    []string
}

func RegisterRoute(grg *gin.RouterGroup, routes []Route, log zap.Logger) {
	for _, route := range routes {
		var handler []gin.HandlerFunc
		for _, domain := range route.Domains {
			var err error
			var endpoint string
			switch domain {
			case "v1":
				endpoint, err = url.JoinPath("v1", route.Path)
				if err != nil {
					log.Fatal("error")
				}

			default:
				log.Fatal(fmt.Sprintf("invalid domain name %v doamin ", domain))
			}
			handler = append(handler, route.Middleware...)
			handler = append(handler, route.Handler)
			grg.Handle(route.Method, endpoint, handler...)
		}
	}

}
