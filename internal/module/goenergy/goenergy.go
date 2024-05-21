package goenergy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"github.com/go-playground/validator"
	"github.com/google/uuid"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants/errors"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants/model/dto"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/module"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/storage/persistence"
	"github.com/paymax2022/Goenergee-Bill-Service/platform/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"go.uber.org/zap"
)

type Config struct {
	ApplicationID string
	ClientID      string
	ClientSecret  string
	RedirectUri   string
}

type VerifyBody struct {
	ServiceType string `json:"serviceType"`
}

type user struct {
	log            *zap.Logger
	IDVendor       int
	CodeUser       string
	BasicAuth      string
	baseURL        string
	password       string
	userDB         persistence.User
	paymentBaseURL string
	callbackURL    string
	conf           Config
	fusionClient   *fusionauth.FusionAuthClient
}

func Init(userdb persistence.User, log *zap.Logger, idVendor int, password, codeUser, basicAuth, baseURL, paymentBaseURL,
	callbackURL string, conf Config, fusionAuthClient *fusionauth.FusionAuthClient) module.User {
	return &user{
		log:            log,
		IDVendor:       idVendor,
		CodeUser:       codeUser,
		baseURL:        baseURL,
		BasicAuth:      basicAuth,
		password:       password,
		userDB:         userdb,
		paymentBaseURL: paymentBaseURL,
		callbackURL:    callbackURL,
		conf:           conf,
		fusionClient:   fusionAuthClient,
	}
}
func (u *user) RegisterUserToFusion(ctxt context.Context, usr dto.FusionUser) (dto.FusionRegistrationResponse, error) {

	tenantResponse, fuerr, err := u.fusionClient.Register(uuid.New().String(), fusionauth.RegistrationRequest{
		DisableDomainBlock: false,
		SkipVerification:   true,
		Registration: fusionauth.UserRegistration{
			ApplicationId: u.conf.ApplicationID,
		},
		User: fusionauth.User{
			Active:      true,
			Email:       usr.Email,
			FirstName:   usr.FirstName,
			LastName:    usr.LastName,
			MobilePhone: usr.MobilePhone,
			SecureIdentity: fusionauth.SecureIdentity{
				Password: usr.Password,
				Verified: true,
			},
		},
	})
	if err != nil {
		u.log.Error("unable to acceess fusion auth service", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, err.Error())
		return dto.FusionRegistrationResponse{}, err
	}
	if fuerr != nil {
		u.log.Error("invalid input to fusion auth service", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, fuerr.Error())
		return dto.FusionRegistrationResponse{}, err
	}
	return dto.FusionRegistrationResponse{
		Token: tenantResponse.Token,
		User: dto.FusionUser{
			Email:       tenantResponse.User.Email,
			FirstName:   tenantResponse.User.FirstName,
			LastName:    tenantResponse.User.LastName,
			MobilePhone: tenantResponse.User.MobilePhone,
		},
	}, nil

}

func (u *user) CreateNewUser(ctx context.Context, nuser dto.FusionUser) (dto.FusionRegistrationResponse, error) {
	validate := validator.New()
	if err := validate.Struct(&nuser); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid input data")
		return dto.FusionRegistrationResponse{}, err
	}
	usr := dto.FusionUser{
		Email:       nuser.Email,
		Password:    nuser.Password,
		FirstName:   nuser.FirstName,
		LastName:    nuser.LastName,
		MobilePhone: nuser.MobilePhone,
	}
	fusionResponse, err := u.RegisterUserToFusion(ctx, usr)
	if err != nil {
		return dto.FusionRegistrationResponse{}, err
	}

	return fusionResponse, nil
}
func (u *user) CreateNewSubUser(ctx context.Context, nuser dto.NewUserRequest) (dto.NewUserRequest, error) {
	validate := validator.New()
	if err := validate.Struct(&nuser); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid input data")
		return dto.NewUserRequest{}, err
	}

	// get access token for the request
	accessToken, err := utils.GetAccessToken("", "")
	if err != nil {
		return dto.NewUserRequest{}, err
	}
	nuser.CodUser = u.CodeUser
	nuser.IDVendor = u.IDVendor
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken.AccessToken,
		"Content-Type":  "application/json",
	}
	body, err := json.Marshal(nuser)
	if err != nil {
		u.log.Error("unable to marshal new user request", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return dto.NewUserRequest{}, err
	}

	request := &dto.APIRequest{
		Method:  http.MethodPost,
		URL:     u.baseURL + string(constants.NEWUSER),
		Body:    body,
		Headers: headers,
	}
	_, status, err := utils.Request(request, http.StatusCreated)
	if err != nil {
		return dto.NewUserRequest{}, err
	}
	if status == http.StatusInternalServerError {
		return dto.NewUserRequest{}, err
	}
	u.userDB.SaveUser(ctx, nuser)
	return nuser, nil
}

func (u *user) ModifyUser(ctx context.Context, nuser dto.UpdateUserRequest) (dto.UpdateUserRequest, error) {
	validate := validator.New()
	if err := validate.Struct(&nuser); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid input data")
		return dto.UpdateUserRequest{}, err
	}
	// get access token for the request
	accessToken, err := utils.GetAccessToken("", "")
	if err != nil {
		return dto.UpdateUserRequest{}, err
	}
	nuser.CodUser = u.CodeUser
	nuser.IdVendor = u.IDVendor
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken.AccessToken,
		"Content-Type":  "application/json",
	}
	body, err := json.Marshal(nuser)
	if err != nil {
		u.log.Error("unable to marshal new user request", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return dto.UpdateUserRequest{}, err
	}

	request := &dto.APIRequest{
		Method:  http.MethodPatch,
		URL:     u.baseURL + string(constants.NEWUSER),
		Body:    body,
		Headers: headers,
	}
	_, status, err := utils.Request(request, http.StatusOK)
	if err != nil {
		return dto.UpdateUserRequest{}, err
	}
	if status == http.StatusInternalServerError {
		return dto.UpdateUserRequest{}, err
	}
	nuser.CodUser = ""
	nuser.IdVendor = 0
	return nuser, nil
}

func (u *user) ValidatePassword(ctx context.Context, nuser dto.ValidatePassword) (dto.ValidatePassword, error) {
	validate := validator.New()
	if err := validate.Struct(&nuser); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid input data")
		return dto.ValidatePassword{}, err
	}
	// get access token for the request
	accessToken, err := utils.GetAccessToken("", "")
	if err != nil {
		return dto.ValidatePassword{}, err
	}
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken.AccessToken,
		"Content-Type":  "application/json",
	}
	nuser.IdVendor = u.IDVendor
	body, err := json.Marshal(nuser)
	if err != nil {
		u.log.Error("unable to marshal new user request", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return dto.ValidatePassword{}, err
	}
	request := &dto.APIRequest{
		Method:  http.MethodPost,
		URL:     u.baseURL + string(constants.VALIDATEUSER),
		Body:    body,
		Headers: headers,
	}
	_, status, err := utils.Request(request, http.StatusOK)
	if err != nil {
		return dto.ValidatePassword{}, err
	}
	if status == http.StatusInternalServerError {
		return dto.ValidatePassword{}, err
	}

	return nuser, nil
}

func (u *user) ChangePassword(ctx context.Context, nuser dto.ChangePasswordRequest) (dto.ChangePasswordRequest, error) {
	validate := validator.New()
	if err := validate.Struct(&nuser); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid input data")
		return dto.ChangePasswordRequest{}, err
	}
	// get access token for the request
	accessToken, err := utils.GetAccessToken("", "")
	if err != nil {
		return dto.ChangePasswordRequest{}, err
	}
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken.AccessToken,
		"Content-Type":  "application/json",
	}
	nuser.IdVendor = u.IDVendor
	body, err := json.Marshal(nuser)
	if err != nil {
		u.log.Error("unable to marshal new user request", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return dto.ChangePasswordRequest{}, err
	}
	request := &dto.APIRequest{
		Method:  http.MethodPatch,
		URL:     u.baseURL + string(constants.CHANGEUSERPASSWORD),
		Body:    body,
		Headers: headers,
	}
	_, status, err := utils.Request(request, http.StatusOK)
	if err != nil {
		return dto.ChangePasswordRequest{}, err
	}
	if status == http.StatusInternalServerError {
		return dto.ChangePasswordRequest{}, err
	}

	return nuser, nil
}

func (u *user) ForgotPassword(ctx context.Context, nuser dto.ForgotPassword) (dto.ForgotPassword, error) {
	validate := validator.New()
	if err := validate.Struct(&nuser); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid input data")
		return dto.ForgotPassword{}, err
	}
	// get access token for the request
	accessToken, err := utils.GetAccessToken("", "")
	if err != nil {
		return dto.ForgotPassword{}, err
	}
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken.AccessToken,
		"Content-Type":  "application/json",
	}
	nuser.IdVendor = u.IDVendor
	body, err := json.Marshal(nuser)
	if err != nil {
		u.log.Error("unable to marshal new user request", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return dto.ForgotPassword{}, err
	}
	request := &dto.APIRequest{
		Method:  http.MethodPost,
		URL:     u.baseURL + string(constants.FORGOTUSERPASSWORD),
		Body:    body,
		Headers: headers,
	}
	_, status, err := utils.Request(request, http.StatusOK)
	if err != nil {
		return dto.ForgotPassword{}, err
	}
	if status == http.StatusInternalServerError {
		return dto.ForgotPassword{}, err
	}

	return nuser, nil
}

func (u *user) SearchUsers(ctx context.Context) ([]dto.SearchUsers, error) {
	usr := dto.Vendor{}
	var users []dto.SearchUsers
	// get access token for the request
	accessToken, err := utils.GetAccessToken("", "")
	if err != nil {
		return []dto.SearchUsers{}, err
	}
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken.AccessToken,
		"Content-Type":  "application/json",
	}
	usr.IdVendor = u.IDVendor
	usr.CodUser = u.CodeUser
	body, err := json.Marshal(usr)
	if err != nil {
		u.log.Error("unable to marshal new user request", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return []dto.SearchUsers{}, err
	}
	request := &dto.APIRequest{
		Method:  http.MethodPost,
		URL:     u.baseURL + string(constants.SEARCHUSERS),
		Body:    body,
		Headers: headers,
	}
	Responsebody, status, err := utils.Request(request, http.StatusOK)
	if err != nil {
		return []dto.SearchUsers{}, err
	}
	if status == http.StatusInternalServerError {
		return []dto.SearchUsers{}, err
	}
	err = json.Unmarshal(Responsebody, &users)
	if err != nil {
		u.log.Error("unable to marshal users response", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return []dto.SearchUsers{}, err
	}

	return users, nil
}

func (u *user) VendorInformation(ctx context.Context) (dto.VendorInformatinResponse, error) {
	usr := dto.Vendor{}
	var vendorInfo dto.VendorInformatinResponse
	// get access token for the request
	accessToken, err := utils.GetAccessToken("", "")
	if err != nil {
		return dto.VendorInformatinResponse{}, err
	}
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken.AccessToken,
		"Content-Type":  "application/json",
	}
	usr.IdVendor = u.IDVendor
	usr.CodUser = u.CodeUser
	body, err := json.Marshal(usr)
	if err != nil {
		u.log.Error("unable to marshal new user request", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return dto.VendorInformatinResponse{}, err
	}
	request := &dto.APIRequest{
		Method:  http.MethodPost,
		URL:     u.baseURL + string(constants.VENDORINFORMATION),
		Body:    body,
		Headers: headers,
	}
	Responsebody, status, err := utils.Request(request, http.StatusOK)
	if err != nil {
		return dto.VendorInformatinResponse{}, err
	}
	if status == http.StatusInternalServerError {
		return dto.VendorInformatinResponse{}, err
	}
	err = json.Unmarshal(Responsebody, &vendorInfo)
	if err != nil {
		u.log.Error("unable to marshal users response", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return dto.VendorInformatinResponse{}, err
	}

	return vendorInfo, nil
}

func (u *user) CriteriaType(ctx context.Context, vendor dto.Vendor) ([]dto.CriteriaTypeResponse, error) {
	validate := validator.New()
	if err := validate.Struct(&vendor); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid input data")
		return []dto.CriteriaTypeResponse{}, err
	}
	var criteriaType []dto.CriteriaTypeResponse
	// get access token for the request
	accessToken, err := utils.GetAccessToken("", "")
	if err != nil {
		return []dto.CriteriaTypeResponse{}, err
	}
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken.AccessToken,
		"Content-Type":  "application/json",
	}
	vendor.IdVendor = u.IDVendor
	body, err := json.Marshal(vendor)
	if err != nil {
		u.log.Error("unable to marshal new user request", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return []dto.CriteriaTypeResponse{}, err
	}
	request := &dto.APIRequest{
		Method:  http.MethodPost,
		URL:     u.baseURL + string(constants.CRITERIATYPE),
		Body:    body,
		Headers: headers,
	}
	Responsebody, status, err := utils.Request(request, http.StatusOK)
	if err != nil {
		return []dto.CriteriaTypeResponse{}, err
	}
	if status == http.StatusInternalServerError {
		return []dto.CriteriaTypeResponse{}, err
	}
	err = json.Unmarshal(Responsebody, &criteriaType)
	if err != nil {
		u.log.Error("unable to marshal users response", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return []dto.CriteriaTypeResponse{}, err
	}

	return criteriaType, nil
}

func (u *user) SearchCustomer(ctx context.Context, sr dto.SearchCustomerRequest) ([]dto.SearchCustomerResponse, error) {
	validate := validator.New()
	if err := validate.Struct(&sr); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid input data")
		return []dto.SearchCustomerResponse{}, err
	}
	var srp []dto.SearchCustomerResponse
	// get access token for the request
	accessToken, err := utils.GetAccessToken("", "")
	if err != nil {
		return []dto.SearchCustomerResponse{}, err
	}
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken.AccessToken,
		"Content-Type":  "application/json",
	}
	sr.IdVendor = u.IDVendor
	body, err := json.Marshal(sr)
	if err != nil {
		u.log.Error("unable to marshal new user request", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return []dto.SearchCustomerResponse{}, err
	}
	request := &dto.APIRequest{
		Method:  http.MethodPost,
		URL:     u.baseURL + string(constants.SEARCHCUSTOMER),
		Body:    body,
		Headers: headers,
	}
	Responsebody, status, err := utils.Request(request, http.StatusOK)
	if err != nil {
		return []dto.SearchCustomerResponse{}, err
	}
	if status == http.StatusInternalServerError {
		return []dto.SearchCustomerResponse{}, err
	}
	err = json.Unmarshal(Responsebody, &srp)
	if err != nil {
		u.log.Error("unable to marshal users response", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return []dto.SearchCustomerResponse{}, err
	}

	return srp, nil
}

func (u *user) CalculatePrice(ctx context.Context, cp dto.CalculatePriceRequest) (dto.CalculatePriceResponse, error) {
	validate := validator.New()
	if err := validate.Struct(&cp); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid input data")
		return dto.CalculatePriceResponse{}, err
	}
	var srp dto.CalculatePriceResponse
	// get access token for the request
	accessToken, err := utils.GetAccessToken("", "")
	if err != nil {
		return dto.CalculatePriceResponse{}, err
	}
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken.AccessToken,
		"Content-Type":  "application/json",
	}
	cp.IdVendor = u.IDVendor
	body, err := json.Marshal(cp)
	if err != nil {
		u.log.Error("unable to marshal new user request", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return dto.CalculatePriceResponse{}, err
	}
	request := &dto.APIRequest{
		Method:  http.MethodPost,
		URL:     u.baseURL + string(constants.CALCUATEPRICE),
		Body:    body,
		Headers: headers,
	}
	Responsebody, status, err := utils.Request(request, http.StatusOK)
	if err != nil {
		return dto.CalculatePriceResponse{}, err
	}
	if status == http.StatusInternalServerError {
		return dto.CalculatePriceResponse{}, err
	}
	err = json.Unmarshal(Responsebody, &srp)
	if err != nil {
		u.log.Error("unable to marshal users response", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return dto.CalculatePriceResponse{}, err
	}

	return srp, nil
}

func (u *user) VerifyMakePayment(ctx context.Context, reference string) (dto.MakePaymentResponse, error) {
	var VerficationResp dto.VerficationResponse
	cp, err := u.userDB.GetPaymentRequestByReferencID(ctx, reference)
	if err != nil {
		return dto.MakePaymentResponse{}, err
	}
	if cp.Status == constants.COMPLETED {
		err := errors.ErrDataAlredyExist.Wrap(fmt.Errorf("payment already complted"), "payment already complted")
		u.log.Warn(err.Error(), zap.Any("paymentReference", reference))
		return dto.MakePaymentResponse{}, err
	}
	body1 := VerifyBody{
		ServiceType: constants.SERVICETYPE,
	}

	binaryBody, _ := json.Marshal(body1)
	headersPaymentVerfication := map[string]string{
		"Content-Length": "<calculated when request is sent>",
		"Content-Type":   "application/json",
	}
	requestPaymentVerification := &dto.APIRequest{
		Method:  http.MethodPost,
		URL:     u.paymentBaseURL + string(constants.VERIFYPAYMENT) + reference,
		Headers: headersPaymentVerfication,
		Body:    binaryBody,
	}
	Responsebody, status, err := utils.HTTPRequest(requestPaymentVerification, http.StatusOK)
	if err != nil {
		return dto.MakePaymentResponse{}, err
	}
	if status != http.StatusOK {
		return dto.MakePaymentResponse{}, err
	}
	err = json.Unmarshal(Responsebody, &VerficationResp)
	if err != nil {
		u.log.Error("unable to marshal payment verification response", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return dto.MakePaymentResponse{}, err
	}
	if VerficationResp.Data.Status != constants.PAYMENT_SUCCESS {
		err = errors.ErrInvalidUserInput.Wrap(fmt.Errorf("payment not complted"), "please complete payment")
		u.log.Warn("payment not complted", zap.Error(err))
		return dto.MakePaymentResponse{}, err
	}
	cp.RequestID = utils.GenerateRandomString(30)
	var srp dto.MakePaymentResponse
	// get access token for the request
	accessToken, err := utils.GetAccessToken("", "")
	if err != nil {
		return dto.MakePaymentResponse{}, err
	}
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken.AccessToken,
		"Content-Type":  "application/json",
	}

	cp.IdVendor = u.IDVendor
	cp.CodUser = u.CodeUser
	body, err := json.Marshal(cp)
	if err != nil {
		u.log.Error("unable to marshal new user request", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return dto.MakePaymentResponse{}, err
	}
	request2 := &dto.APIRequest{
		Method:  http.MethodPost,
		URL:     u.baseURL + string(constants.MAKEPAYMENT),
		Body:    body,
		Headers: headers,
	}
	for i := 0; i < 3; i++ {
		Responsebody2, status, err := utils.Request(request2, http.StatusCreated)
		if err != nil {
			continue
		}
		if status == http.StatusInternalServerError {
			continue
		}
		err = json.Unmarshal(Responsebody2, &srp)
		if err != nil {
			u.log.Error("unable to marshal users response", zap.Error(err))
			err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
			return dto.MakePaymentResponse{}, err
		}
		currentTime := time.Now()
		currentTimeMillis := currentTime.UnixNano() / int64(time.Millisecond)

		u.userDB.UpdateTransaction(ctx, dto.Transactions{
			ID:                cp.ID,
			CodUser:           srp.CodUser,
			MeterSerial:       srp.MeterSerial,
			Account:           srp.Account,
			DebtPayment:       srp.DebtPayment,
			TotalPayment:      srp.TotalPayment,
			AccountBalance:    srp.AccountBalance,
			UnitsPayment:      srp.UnitsPayment,
			Units:             srp.Units,
			UnitsType:         srp.UnitsType,
			PaymentDate:       srp.PaymentDate,
			Receipt:           srp.Receipt,
			CustomerName:      srp.CustomerName,
			TariffDescription: srp.TariffDescription,
			UnitsTopUp:        srp.UnitsTopUp,
			Comment:           srp.Comment,
			Listtoken:         srp.Listtoken,
			KeyDataSGC:        srp.KeyDataSGC,
			KeyDataTI:         srp.KeyDataTI,
			KeyDataKRN:        srp.KeyDataKRN,
			RequestID:         srp.RequestID,
			Channel:           srp.Channel,
			MapUnits:          srp.MapUnits,
			MapAmount:         srp.MapAmount,
			MapTokens:         srp.MapTokens,
			KctTokens:         srp.KctTokens,
			Date:              currentTimeMillis,
			Status:            constants.COMPLETED,
			Reference:         reference,
		})
		return srp, nil

	}
	return dto.MakePaymentResponse{}, err

}

func (u *user) RetrieveDetailedPaymentInformation(ctx context.Context, cp dto.RetrieveDetailedPaymentInformationRequest) (dto.RetrieveDetailedPaymentInformationResponse, error) {
	validate := validator.New()
	if err := validate.Struct(&cp); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid input data")
		return dto.RetrieveDetailedPaymentInformationResponse{}, err
	}
	var srp dto.RetrieveDetailedPaymentInformationResponse
	// get access token for the request
	accessToken, err := utils.GetAccessToken("", "")
	if err != nil {
		return dto.RetrieveDetailedPaymentInformationResponse{}, err
	}
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken.AccessToken,
		"Content-Type":  "application/json",
	}
	cp.IdVendor = u.IDVendor
	body, err := json.Marshal(cp)
	if err != nil {
		u.log.Error("unable to marshal new user request", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return dto.RetrieveDetailedPaymentInformationResponse{}, err
	}
	request := &dto.APIRequest{
		Method:  http.MethodPost,
		URL:     u.baseURL + string(constants.PAYMENTINFO),
		Body:    body,
		Headers: headers,
	}
	Responsebody, status, err := utils.Request(request, http.StatusOK)
	if err != nil {
		return dto.RetrieveDetailedPaymentInformationResponse{}, err
	}
	if status == http.StatusInternalServerError {
		return dto.RetrieveDetailedPaymentInformationResponse{}, err
	}
	err = json.Unmarshal(Responsebody, &srp)
	if err != nil {
		u.log.Error("unable to marshal users response", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return dto.RetrieveDetailedPaymentInformationResponse{}, err
	}

	return srp, nil
}

func (u *user) ShiftEnquiries(ctx context.Context, cp dto.ShiftEnquiriesRequest) ([]dto.ShiftEnquiriesResponse, error) {
	validate := validator.New()
	if err := validate.Struct(&cp); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid input data")
		return []dto.ShiftEnquiriesResponse{}, err
	}

	// validate password
	password, err := u.userDB.GetPassword(ctx)
	if err != nil {
		return []dto.ShiftEnquiriesResponse{}, err
	}
	if utils.ComparePasswords(password, cp.PassWord) != nil {
		u.log.Error("error in comparing the passwords ")
		err = errors.ErrInvalidUserInput.Wrap(err, "incorrect password")
		return []dto.ShiftEnquiriesResponse{}, err
	}
	numStr := strconv.Itoa(cp.PaymentDate)
	if len(numStr) < 5 {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid date")
		return []dto.ShiftEnquiriesResponse{}, err
	}
	firstFiveDigits := numStr[:5]
	date := fmt.Sprintf("%s%d%d%d%d%d%d%d%d", firstFiveDigits, 0, 0, 0, 0, 0, 0, 0, 0)
	num, _ := strconv.Atoi(date)
	num2 := num + 100000000
	cp.PaymentDate = num
	cp.PaymentDateTo = num2
	return u.userDB.GetShiftEnequiries(ctx, cp)
}

func (u *user) CustomerEnquiries(ctx context.Context, cp dto.CustomerEnquiriesRequest) ([]dto.CustomerEnquiriesResponse, error) {

	//
	validate := validator.New()
	if err := validate.Struct(&cp); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid input data")
		return []dto.CustomerEnquiriesResponse{}, err
	}
	var srp []dto.CustomerEnquiriesResponse
	// get access token for the request
	accessToken, err := utils.GetAccessToken("", "")
	if err != nil {
		return []dto.CustomerEnquiriesResponse{}, err
	}
	headers := map[string]string{
		"Authorization": "Bearer " + accessToken.AccessToken,
		"Content-Type":  "application/json",
	}
	cp.IDVendor = u.IDVendor
	body, err := json.Marshal(cp)
	if err != nil {
		u.log.Error("unable to marshal new user request", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return []dto.CustomerEnquiriesResponse{}, err
	}
	request := &dto.APIRequest{
		Method:  http.MethodPost,
		URL:     u.baseURL + string(constants.VENCUSTOMERENQUIRIES),
		Body:    body,
		Headers: headers,
	}
	Responsebody, status, err := utils.Request(request, http.StatusOK)
	if err != nil {
		return []dto.CustomerEnquiriesResponse{}, err
	}
	if status == http.StatusInternalServerError {
		return []dto.CustomerEnquiriesResponse{}, err
	}
	err = json.Unmarshal(Responsebody, &srp)
	if err != nil {
		u.log.Error("unable to marshal users response", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return []dto.CustomerEnquiriesResponse{}, err
	}

	return srp, nil
}

func (u *user) GetVendorTransactions(ctx context.Context, cp dto.VendorTransactionRequest) ([]dto.Transactions, error) {
	validate := validator.New()
	if err := validate.Struct(&cp); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid input data")
		return []dto.Transactions{}, err
	}

	// validate password
	password, err := u.userDB.GetPassword(ctx)
	if err != nil {
		return []dto.Transactions{}, err
	}
	if utils.ComparePasswords(password, cp.PassWord) != nil {
		u.log.Error("error in comparing the passwords ")
		err = errors.ErrInvalidUserInput.Wrap(err, "incorrect password")
		return []dto.Transactions{}, err
	}
	return u.userDB.GetVendorTransactions(ctx, cp)
}
func (u *user) SetVendorPassword(ctx context.Context, password string) error {
	hashPassword, err := utils.GenerateHash(password)
	if err != nil {
		err = errors.ErrUnExpectedError.Wrap(err, err.Error())
		u.log.Error(err.Error(), zap.Any("password", password))
		return err

	}

	return u.userDB.SaveVendorPassword(ctx, hashPassword)
}
func (u *user) MakePaymentRequest(ctx context.Context, cp dto.MakePaymentRequest) (dto.PaymentRequestResponse, error) {
	transactionType := "POSTPAID"
	var rsp dto.InitPaymentResponse
	validate := validator.New()
	if err := validate.Struct(&cp); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid input data")
		return dto.PaymentRequestResponse{}, err
	}
	comm, err := u.userDB.GetCommission(ctx)
	if err != nil {
		return dto.PaymentRequestResponse{}, err
	}
	if cp.TotalPayment < 1000 {
		u.log.Warn("payment less than 1000 not allowed ", zap.Any("amount", cp.TotalPayment))
		err = errors.ErrInvalidUserInput.Wrap(fmt.Errorf("payment less than 100"), "payment less than 1000 not allowed")
		return dto.PaymentRequestResponse{}, err
	}
	amount := (cp.TotalPayment + comm)
	initPayment := dto.InitializePaymentRequest{
		Email:       cp.Email,
		Amount:      amount,
		CallbackURL: u.callbackURL,
		ServiceType: constants.SERVICETYPE,
	}
	body, err := json.Marshal(initPayment)
	if err != nil {
		u.log.Error("unable to marshal new user request", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return dto.PaymentRequestResponse{}, err
	}
	headers := map[string]string{
		"Content-Type":   "application/json",
		"Content-Length": "<calculated when request is sent>",
	}
	request := &dto.APIRequest{
		Method:  http.MethodPost,
		URL:     u.paymentBaseURL + string(constants.INITIALIZEPAYMENT),
		Body:    body,
		Headers: headers,
	}
	Responsebody, status, err := utils.HTTPRequest(request, http.StatusOK)
	if err != nil {
		return dto.PaymentRequestResponse{}, err
	}
	if status == http.StatusInternalServerError {
		return dto.PaymentRequestResponse{}, err
	}

	err = json.Unmarshal(Responsebody, &rsp)
	if err != nil {
		u.log.Error("unable to marshal users response", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, "unable to marshal data")
		return dto.PaymentRequestResponse{}, err
	}
	currentTime := time.Now()
	currentTimeMillis := currentTime.UnixNano() / int64(time.Millisecond)

	culculate, err := u.CalculatePrice(ctx, dto.CalculatePriceRequest{
		IdVendor:    u.IDVendor,
		CodUser:     u.CodeUser,
		MeterSerial: cp.MeterSerial,
		Account:     cp.Account,
	})
	if strings.Contains(culculate.TariffDescription, "Prepaid") {
		if culculate.AccountBalance > 0 {
			u.log.Error("you have upaid DebtPayment", zap.Error(err))
			err = errors.ErrInvalidUserInput.Wrap(err, fmt.Sprintf("you have upaid Debt Payment to pay %f", culculate.AccountBalance))
			return dto.PaymentRequestResponse{}, err
		}
	}

	if err != nil {
		return dto.PaymentRequestResponse{}, err
	}
	sechCustomerTransactionType, err := u.SearchCustomer(ctx, dto.SearchCustomerRequest{
		IdVendor:     u.IDVendor,
		CodUser:      u.CodeUser,
		Value:        cp.MeterSerial,
		CodType:      constants.CodeType,
		TotalPayment: 1000000,
	})
	if len(sechCustomerTransactionType) < 1 {
		u.log.Error("unable to get customer", zap.Error(fmt.Errorf("unable to get customer")))
		err = errors.ErrInvalidUserInput.Wrap(err, fmt.Sprintf("unable to get customer with meter number %s", cp.MeterSerial))
		return dto.PaymentRequestResponse{}, err

	}
	if sechCustomerTransactionType[0].IndicatorPrePostAccount == 1 {
		transactionType = "PREPAID"
	}
	makePaymentRequestResponse := dto.PaymentRequestResponse{
		CheckoutURL: rsp.Data.AuthorizationURL,
		Transaction: rsp.Data.Reference,
		Status:      "INITIATED",
		Amount:      cp.TotalPayment,
		MeterNumber: culculate.MeterSerial,
		Name:        culculate.CustomerName,
		Address:     culculate.ServiceAddress,
		Product:     culculate.TariffDescription,
		Commission:  comm,
	}
	u.userDB.SaveTrasnaction(ctx, dto.Transactions{
		ID:                primitive.NewObjectID(),
		CodUser:           cp.CodUser,
		MeterSerial:       cp.MeterSerial,
		Account:           cp.Account,
		DebtPayment:       cp.DebtPayment,
		TotalPayment:      cp.TotalPayment,
		AccountBalance:    cp.AccountBalance,
		UnitsPayment:      cp.UnitsPayment,
		Units:             cp.Units,
		UnitsType:         cp.UnitsType,
		TariffDescription: cp.TariffDescription,
		Comment:           cp.Comment,
		RequestID:         cp.RequestID,
		Channel:           cp.Channel,
		Date:              currentTimeMillis,
		Status:            constants.PENDING,
		Reference:         rsp.Data.Reference,
		Commission:        comm,
		Email:             cp.Email,
		Type:              transactionType,
	})
	return makePaymentRequestResponse, nil
}

func (u *user) GetSession(ctx context.Context, sessionRequest dto.GetSessionRequest) (dto.AuthResponse, error) {
	codeUser, err := u.userDB.GetCodeUserUsingEmail(ctx, sessionRequest.Email)
	if err != nil {
		return dto.AuthResponse{}, err
	}
	return utils.GetAccessToken(codeUser, sessionRequest.Password)
}
func (u *user) GetReceiptUsingToken(ctx context.Context, token string) (dto.MakePaymentResponse, error) {
	return u.userDB.GetReceiptUsingToken(ctx, token)
}
func (u *user) GetReceiptUsingFilters(ctx context.Context, receipt dto.ReceiptFilter) ([]dto.MakePaymentResponse, error) {
	if receipt.PerPage == 0 {
		receipt.PerPage = 10
	}
	if receipt.PageNumber == 0 {
		receipt.PageNumber = 1
	}
	validate := validator.New()
	if err := validate.Struct(&receipt); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, "invalid input data")
		return []dto.MakePaymentResponse{}, err
	}
	filter := bson.M{}
	if receipt.Email != "" {
		filter["email"] = receipt.Email
	}
	if receipt.RequestID != "" {
		filter["requestID"] = receipt.RequestID
	}
	return u.userDB.GetReceiptUsingFilters(ctx, filter, receipt.PageNumber, receipt.PerPage)
}

func (u *user) GetTransactionStatics(ctx context.Context) (constants.TransactionStatusResponse, error) {
	transctionStaticcs := constants.TransactionStatusResponse{}
	tempTransaction := []constants.TrasactionStatus{}
	for _, status := range constants.TransactionStatus {
		count, err := u.userDB.CountTransactionByStatus(ctx, status)
		if err != nil {
			return constants.TransactionStatusResponse{}, err

		}
		tempTransaction = append(tempTransaction, constants.TrasactionStatus{
			Status: status,
			Count:  count,
		})

	}
	transctionStaticcs.Transactions = tempTransaction
	vi, err := u.VendorInformation(ctx)
	if err != nil {
		return constants.TransactionStatusResponse{}, err
	}
	transctionStaticcs.WalletBalance = vi.Balance
	return transctionStaticcs, nil
}

func (u *user) GetTransactionByTransactionType(ctx context.Context, filter dto.GetRransactionByTransactionTypeRequest) ([]dto.MakePaymentResponse, error) {
	if filter.PerPage == 0 {
		filter.PerPage = 10
	}
	if filter.PageNumber == 0 {
		filter.PageNumber = 1
	}
	validate := validator.New()
	if err := validate.Struct(&filter); err != nil {
		u.log.Error("validation error ", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, err.Error())
		return []dto.MakePaymentResponse{}, err
	}
	filterR := bson.M{
		"type": filter.Type,
	}

	return u.userDB.GetReceiptUsingFilters(ctx, filterR, filter.PageNumber, filter.PerPage)
}

func (u *user) Token(ctx context.Context, code string) (dto.AccessToken, error) {
	tenantResponse, fuerr, err := u.fusionClient.ExchangeOAuthCodeForAccessToken(code, u.conf.ClientID, u.conf.ClientSecret, u.conf.RedirectUri)
	if err != nil {
		u.log.Error("unable to acceess fusion auth service", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, err.Error())
		return dto.AccessToken{}, err
	}
	if fuerr != nil {
		u.log.Error("invalid input to fusion auth service", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, fuerr.ErrorDescription)
		return dto.AccessToken{}, err
	}
	return dto.AccessToken{
		AccessToken:  tenantResponse.AccessToken,
		RefreshToken: tenantResponse.RefreshToken,
	}, nil
}
func (u *user) Profile(ctx context.Context, userID string) (dto.FusionUser, error) {
	userIDs := []string{userID}
	tenantResponse, fuerr, err := u.fusionClient.SearchUsersByIds(userIDs)
	if err != nil {
		u.log.Error("unable to acceess fusion auth service", zap.Error(err))
		err = errors.ErrUnExpectedError.Wrap(err, err.Error())
		return dto.FusionUser{}, err
	}
	if fuerr != nil {
		u.log.Error("invalid input to fusion auth service", zap.Error(err))
		err = errors.ErrInvalidUserInput.Wrap(err, fuerr.Error())
		return dto.FusionUser{}, err
	}
	if len(tenantResponse.Users) < 1 {
		u.log.Error("user not found")
		err = errors.ErrInvalidUserInput.Wrap(fmt.Errorf("user not found"), "user not found with id "+userID)
		return dto.FusionUser{}, err
	}
	return dto.FusionUser{
		Email:       tenantResponse.Users[0].Email,
		FirstName:   tenantResponse.Users[0].FirstName,
		LastName:    tenantResponse.Users[0].LastName,
		MobilePhone: tenantResponse.Users[0].MobilePhone,
	}, nil
}
