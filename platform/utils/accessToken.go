package utils

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants/model/dto"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func SetAccessToken(codUser, password string) (dto.AuthResponse, error) {
	log, _ := zap.NewProduction()
	defer log.Sync()
	baseURL := viper.GetString("baseURL")
	basicAuth := viper.GetString("basicAuth")
	idVendor := viper.GetString("idVendor")
	// codUser := viper.GetString("codUser")
	headers := map[string]string{
		"Authorization": fmt.Sprintf("Basic %s", basicAuth),
	}
	body := map[string]string{
		"grant_type": "password",
		"username":   fmt.Sprintf("%s#%s", idVendor, codUser),
		"password":   password,
	}

	request := &dto.APIRequestAccessTokenRequest{
		Method:  http.MethodPost,
		URL:     baseURL + string(constants.TOKEN),
		Body:    body,
		Headers: headers,
	}

	data, _, err := AccessTokenRequest(request, []int{http.StatusOK})
	if err != nil {
		return dto.AuthResponse{}, err
	}
	var authResponse dto.AuthResponse
	err = json.Unmarshal(data, &authResponse)
	if err != nil {
		log.Error("unable to bind response to AuthResponse", zap.Any("data", string(data)))
		return dto.AuthResponse{}, fmt.Errorf("error unmarshaling response to AuthResponse: %w", err)
	}
	return authResponse, nil

}
func GetAccessToken(user, password string) (dto.AuthResponse, error) {
	usr := ""
	passwd := ""
	if user == "" {
		usr = viper.GetString("codUser")
		passwd = viper.GetString("password")

	} else {
		usr = user
		passwd = password
	}
	access, err := SetAccessToken(usr, passwd)
	if err != nil {
		return dto.AuthResponse{}, err
	}
	return access, nil

}
