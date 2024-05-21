package utils

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants/errors"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants/model/dto"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func contains(target int, arr []int) bool {
	for _, element := range arr {
		if target == element {
			return true
		}
	}
	return false
}
func handleError(data []byte, errStatus int, log *zap.Logger) ([]byte, int, error) {
	var errordata dto.ErrorResponse
	err := json.Unmarshal(data, &errordata)
	if err != nil {
		log.Error("unable to bind error response to dto.ErrorResponse", zap.Error(err))
		return nil, errStatus, fmt.Errorf("unexpected status code: %v", errStatus)
	}
	log.Error(errordata.MsgDeveloper, zap.Any("status", errordata.Code), zap.Any("message", errordata.MsgDeveloper))
	err = errors.ErrInvalidUserInput.Wrap(fmt.Errorf("error %s", errordata.MsgUser), errordata.MsgUser)
	return nil, errStatus, err
}
func Request(req *dto.APIRequest, successStatus int) ([]byte, int, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	log, err := zap.NewProduction()
	if err != nil {
		return nil, 0, fmt.Errorf("error creating logger: %w", err)
	}
	defer log.Sync()

	var (
		resp *http.Response
	)

	for i := 0; i < 3; i++ {

		newReq, err := http.NewRequest(req.Method, req.URL, bytes.NewBuffer(req.Body))
		if err != nil {
			return nil, 0, fmt.Errorf("error creating HTTP request: %w", err)
		}

		// Set Content-Type header to JSON
		newReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		for key, value := range req.Headers {
			newReq.Header.Set(key, value)
		}

		resp, err = client.Do(newReq)
		if err == nil {
			break
		}
		if i == 2 {
			log.Error("unable to read response for access point", zap.Error(err))
			return nil, 0, fmt.Errorf("error reading response body: %w", err)
		}
	}

	defer func() {
		if resp != nil {
			resp.Body.Close()
		}
	}()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("unable to read response for access point", zap.Error(err))
		return nil, resp.StatusCode, fmt.Errorf("error reading response body: %w", err)
	}
	if resp.StatusCode != successStatus {
		return handleError(data, resp.StatusCode, log)
	}

	return data, resp.StatusCode, nil
}
func HTTPRequest(req *dto.APIRequest, successStatus int) ([]byte, int, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	log, err := zap.NewProduction()
	if err != nil {
		return nil, 0, fmt.Errorf("error creating logger: %w", err)
	}
	defer log.Sync()

	var (
		resp *http.Response
	)

	for i := 0; i < 3; i++ {

		newReq, err := http.NewRequest(req.Method, req.URL, bytes.NewBuffer(req.Body))
		if err != nil {
			return nil, 0, fmt.Errorf("error creating HTTP request: %w", err)
		}
		for key, value := range req.Headers {
			newReq.Header.Set(key, value)
		}

		resp, err = client.Do(newReq)
		if err == nil {
			break
		}
		if i == 2 {
			log.Error("unable to read response for access point", zap.Error(err))
			return nil, 0, fmt.Errorf("error reading response body: %w", err)
		}
	}

	defer func() {
		if resp != nil {
			resp.Body.Close()
		}
	}()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("unable to read response for access point", zap.Error(err))
		return nil, resp.StatusCode, fmt.Errorf("error reading response body: %w", err)
	}
	if resp.StatusCode != successStatus {
		return handleError(data, resp.StatusCode, log)
	}

	return data, resp.StatusCode, nil
}

func AccessTokenRequest(req *dto.APIRequestAccessTokenRequest, status []int) ([]byte, int, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second, // Set a timeout to avoid hanging indefinitely
	}

	log, err := zap.NewProduction()
	if err != nil {
		return nil, 0, fmt.Errorf("error creating logger: %w", err)
	}
	defer log.Sync()

	var (
		resp *http.Response
	)

	for i := 0; i < 3; i++ {
		// Encode request body as URL-encoded string
		form := url.Values{}
		for key, value := range req.Body {
			form.Set(key, value)
		}

		newReq, err := http.NewRequest(req.Method, req.URL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, 0, fmt.Errorf("error creating HTTP request: %w", err)
		}

		// Set Content-Type header to application/x-www-form-urlencoded
		newReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		for key, value := range req.Headers {
			newReq.Header.Set(key, value)
		}

		resp, err = client.Do(newReq)
		if err == nil {
			break
		}
		if i == 2 {
			log.Error("unable to read response for access point", zap.Error(err))
			return nil, 0, fmt.Errorf("error reading response body: %w", err)
		}
	}

	defer func() {
		if resp != nil {
			resp.Body.Close()
		}
	}()

	if !contains(resp.StatusCode, status) {
		log.Error("unable to access get access token endpoint ", zap.Int("status", resp.StatusCode))
		return nil, resp.StatusCode, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("unable to read response for access point", zap.Error(err))
		return nil, resp.StatusCode, fmt.Errorf("error reading response body: %w", err)
	}
	return data, resp.StatusCode, nil
}

func RequestValidateToken(token string) (dto.AuthServiceResponse, error) {
	requestURL := fmt.Sprintf("%s%s", viper.GetString("auth_domain"), constants.VERIFYTOKEN)

	// Create a form data object
	formData := url.Values{}
	accessToken := token
	formData.Add("accessToken", accessToken)

	// Convert form data to URL-encoded string
	requestBody := bytes.NewBufferString(formData.Encode())

	// Create a new POST request
	req, err := http.NewRequest("POST", requestURL, requestBody)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return dto.AuthServiceResponse{}, err
	}

	// Set the Content-Type header
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send the request using the http client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return dto.AuthServiceResponse{}, err
	}
	defer resp.Body.Close()

	// Read the response body
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return dto.AuthServiceResponse{}, err
	}

	var p dto.AuthServiceResponse
	if err := json.Unmarshal(responseBody, &p); err != nil {
		fmt.Println("Error reading response:", err)
		return dto.AuthServiceResponse{}, err
	}
	return p, nil
}
