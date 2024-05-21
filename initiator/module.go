package initiator

import (
	"net/http"
	"net/url"
	"time"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/module"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/module/goenergy"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type Module struct {
	User module.User
}

var httpClient = &http.Client{
	Timeout: time.Second * 10,
}

func InitModule(log *zap.Logger, persistenceDb Persistence) Module {
	authDomain := viper.GetString("fusion.auth_domain")
	authAPIKey := viper.GetString("fusion.api_key")
	var baseURL, _ = url.Parse(authDomain)
	var client = fusionauth.NewClient(httpClient, baseURL, authAPIKey)
	return Module{
		User: goenergy.Init(persistenceDb.User, log, viper.GetInt("idVendor"),
			viper.GetString("password"),
			viper.GetString("codUser"),
			viper.GetString("basicAuth"),
			viper.GetString("baseURL"),
			viper.GetString("PaymentBaseURL"),
			viper.GetString("frontend_redirect_url"), goenergy.Config{
				ApplicationID: viper.GetString("fusion.application_id"),
				ClientID:      viper.GetString("fusion.client_id"),
				ClientSecret:  viper.GetString("fusion.client_secret"),
				RedirectUri:   viper.GetString("fusion.redirect_uri"),
			},
			client,
		),
	}
}
