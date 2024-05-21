package handler

import "github.com/gin-gonic/gin"

type User interface {
	CreateUser(c *gin.Context)
	ModifyUser(c *gin.Context)
	ValidatePassword(c *gin.Context)
	ChangePassword(c *gin.Context)
	ForgotPassword(c *gin.Context)
	SearchUsers(c *gin.Context)
	VendorInformation(c *gin.Context)
	CriteriaType(c *gin.Context)
	CalculatePrice(c *gin.Context)
	MakePayment(c *gin.Context)
	SearchCustomer(c *gin.Context)
	RetrieveDetailedPaymentInformation(c *gin.Context)
	ShiftEnquiries(c *gin.Context)
	CustomerEnquiries(c *gin.Context)
	GetVendorTransactions(c *gin.Context)
	SetVendorPassword(c *gin.Context)
	VerifyMakePayment(c *gin.Context)
	GetSessionRequest(c *gin.Context)
	GetReceiptUsingToken(c *gin.Context)
	CreateNewSubUser(c *gin.Context)
	GetReceiptUsingFilters(c *gin.Context)
	GetTransactionStatics(c *gin.Context)
	GetTransactionByTransactionType(c *gin.Context)
	Token(c *gin.Context)
	Profile(c *gin.Context)
}
