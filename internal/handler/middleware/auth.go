package middleware

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	// Import for binding.JSON
)

var httpClient = &http.Client{
	Timeout: time.Second * 10,
}

func AuthMiddlewAre() gin.HandlerFunc {
	return func(c *gin.Context) {

		authURL := viper.GetString("fusion.auth_domain")
		AuthAPIKey := viper.GetString("fusion.api_key")
		var baseURL, _ = url.Parse(authURL)
		log, _ := zap.NewProduction()
		defer log.Sync()
		var client = fusionauth.NewClient(httpClient, baseURL, AuthAPIKey)

		// Get the token from the request header
		authHeader := c.GetHeader("Authorization")
		authHeaderParts := strings.Split(authHeader, " ")
		if len(authHeaderParts) != 2 {
			log.Warn("invalid authorization header")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid authorization header"})
			return
		}

		// Validate the token
		response, err := client.ValidateJWT(authHeaderParts[1])
		if err != nil {
			log.Error(err.Error(), zap.Any("data", authHeaderParts[1]))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			return
		}
		if response.Jwt.Sub == "" {
			log.Error("empty sub", zap.Any("data", authHeaderParts[1]))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "unkown token"})
			return
		}
		c.Set("userID", response.Jwt.Sub)

		c.Next()
	}
}
