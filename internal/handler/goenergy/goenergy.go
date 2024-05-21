package goenergy

import (
	"fmt"
	"net/http"

	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants/errors"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants/model/dto"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants/model/response"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/handler"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/module"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type user struct {
	UserModule module.User
	Logger     zap.Logger
}

func Init(userModule module.User, log zap.Logger) handler.User {
	return &user{
		UserModule: userModule,
		Logger:     log,
	}
}
func (u *user) CreateUser(c *gin.Context) {
	var usr dto.FusionUser
	if err := c.ShouldBind(&usr); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.NewUserRequest")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.CreateNewUser(c, usr)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) ModifyUser(c *gin.Context) {
	var usr dto.UpdateUserRequest
	if err := c.ShouldBind(&usr); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.UpdateUserRequest")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.ModifyUser(c, usr)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) ValidatePassword(c *gin.Context) {
	var usr dto.ValidatePassword
	if err := c.ShouldBind(&usr); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.ValidatePassword")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.ValidatePassword(c, usr)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) ChangePassword(c *gin.Context) {
	var usr dto.ChangePasswordRequest
	if err := c.ShouldBind(&usr); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.ChangePasswordRequest")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.ChangePassword(c, usr)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) ForgotPassword(c *gin.Context) {
	var usr dto.ForgotPassword
	if err := c.ShouldBind(&usr); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.ForgotPassword")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.ForgotPassword(c, usr)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) SearchUsers(c *gin.Context) {

	res, err := u.UserModule.SearchUsers(c)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) VendorInformation(c *gin.Context) {

	res, err := u.UserModule.VendorInformation(c)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) CriteriaType(c *gin.Context) {
	var cri dto.Vendor
	if err := c.ShouldBind(&cri); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.Vendor")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.CriteriaType(c, cri)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) SearchCustomer(c *gin.Context) {
	var cri dto.SearchCustomerRequest
	if err := c.ShouldBind(&cri); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.SearchCustomerRequest")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.SearchCustomer(c, cri)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) CalculatePrice(c *gin.Context) {
	var cp dto.CalculatePriceRequest
	if err := c.ShouldBind(&cp); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.CalculatePriceRequest")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.CalculatePrice(c, cp)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) MakePayment(c *gin.Context) {
	var cp dto.MakePaymentRequest
	if err := c.ShouldBind(&cp); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.MakePaymentRequest")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.MakePaymentRequest(c, cp)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) RetrieveDetailedPaymentInformation(c *gin.Context) {
	var cp dto.RetrieveDetailedPaymentInformationRequest
	if err := c.ShouldBind(&cp); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.RetrieveDetailedPaymentInformationRequest")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.RetrieveDetailedPaymentInformation(c, cp)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)

}
func (u *user) ShiftEnquiries(c *gin.Context) {
	var cp dto.ShiftEnquiriesRequest
	if err := c.ShouldBind(&cp); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.ShiftEnquiriesRequest")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.ShiftEnquiries(c, cp)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) CustomerEnquiries(c *gin.Context) {
	var cp dto.CustomerEnquiriesRequest
	if err := c.ShouldBind(&cp); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.ShiftEnquiriesRequest")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.CustomerEnquiries(c, cp)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)

}
func (u *user) GetVendorTransactions(c *gin.Context) {
	var cp dto.VendorTransactionRequest
	if err := c.ShouldBind(&cp); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.VendorTransactionRequest")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.GetVendorTransactions(c, cp)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) SetVendorPassword(c *gin.Context) {
	var cp dto.VendoerRequirement
	if err := c.ShouldBind(&cp); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.VendorTransactionRequest")
		_ = c.Error(err)
		return
	}
	err := u.UserModule.SetVendorPassword(c, cp.Password)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, cp)
}
func (u *user) VerifyMakePayment(c *gin.Context) {
	reference := c.Param("reference")
	if reference == "" {
		err := errors.ErrInvalidUserInput.Wrap(fmt.Errorf("empty reference"), "unable to bind user to dto.VendorTransactionRequest")
		_ = c.Error(err)
		return
	}
	payment, err := u.UserModule.VerifyMakePayment(c, reference)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusOK, payment)

}
func (u *user) GetSessionRequest(c *gin.Context) {
	var cp dto.GetSessionRequest
	if err := c.ShouldBind(&cp); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.GetSessionRequest")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.GetSession(c, cp)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)

}
func (u *user) GetReceiptUsingToken(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		err := errors.ErrInvalidUserInput.Wrap(fmt.Errorf("empty token"), "empty token")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.GetReceiptUsingToken(c, token)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)

}
func (u *user) CreateNewSubUser(c *gin.Context) {
	var cp dto.NewUserRequest
	if err := c.ShouldBind(&cp); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.NewUserRequest")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.CreateNewSubUser(c, cp)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) GetReceiptUsingFilters(c *gin.Context) {
	var cp dto.ReceiptFilter
	if err := c.ShouldBind(&cp); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.ReceiptFilter")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.GetReceiptUsingFilters(c, cp)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) GetTransactionStatics(c *gin.Context) {
	res, err := u.UserModule.GetTransactionStatics(c)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusOK, res)
}
func (u *user) GetTransactionByTransactionType(c *gin.Context) {
	var cp dto.GetRransactionByTransactionTypeRequest
	if err := c.ShouldBind(&cp); err != nil {
		err := errors.ErrInvalidUserInput.Wrap(err, "unable to bind user to dto.GetRransactionByTransactionTypeRequest")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.GetTransactionByTransactionType(c, cp)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusCreated, res)
}
func (u *user) Token(c *gin.Context) {
	code := c.Param("code")
	if code == "" {
		err := errors.ErrInvalidUserInput.Wrap(fmt.Errorf("empty code"), "empty code")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.Token(c, code)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusOK, res)
}
func (u *user) Profile(c *gin.Context) {
	userID := c.GetString("userID")
	if userID == "" {
		err := errors.ErrInvalidUserInput.Wrap(fmt.Errorf("empty userID"), "empty userID")
		_ = c.Error(err)
		return
	}
	res, err := u.UserModule.Profile(c, userID)
	if err != nil {
		_ = c.Error(err)
		return
	}
	response.SendSuccessResponse(c, http.StatusOK, res)
}
