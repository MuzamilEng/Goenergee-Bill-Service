package module

import (
	"context"

	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants/model/dto"
)

type User interface {
	CreateNewUser(ctx context.Context, nuser dto.FusionUser) (dto.FusionRegistrationResponse, error)
	ModifyUser(ctx context.Context, nuser dto.UpdateUserRequest) (dto.UpdateUserRequest, error)
	ValidatePassword(ctx context.Context, nuser dto.ValidatePassword) (dto.ValidatePassword, error)
	ChangePassword(ctx context.Context, nuser dto.ChangePasswordRequest) (dto.ChangePasswordRequest, error)
	ForgotPassword(ctx context.Context, nuser dto.ForgotPassword) (dto.ForgotPassword, error)
	SearchUsers(ctx context.Context) ([]dto.SearchUsers, error)
	VendorInformation(ctx context.Context) (dto.VendorInformatinResponse, error)
	CriteriaType(ctx context.Context, vendor dto.Vendor) ([]dto.CriteriaTypeResponse, error)
	SearchCustomer(ctx context.Context, sr dto.SearchCustomerRequest) ([]dto.SearchCustomerResponse, error)
	CalculatePrice(ctx context.Context, cp dto.CalculatePriceRequest) (dto.CalculatePriceResponse, error)
	VerifyMakePayment(ctx context.Context, reference string) (dto.MakePaymentResponse, error)
	RetrieveDetailedPaymentInformation(ctx context.Context, cp dto.RetrieveDetailedPaymentInformationRequest) (dto.RetrieveDetailedPaymentInformationResponse, error)
	ShiftEnquiries(ctx context.Context, cp dto.ShiftEnquiriesRequest) ([]dto.ShiftEnquiriesResponse, error)
	CustomerEnquiries(ctx context.Context, cp dto.CustomerEnquiriesRequest) ([]dto.CustomerEnquiriesResponse, error)
	GetVendorTransactions(ctx context.Context, cp dto.VendorTransactionRequest) ([]dto.Transactions, error)
	SetVendorPassword(ctx context.Context, password string) error
	MakePaymentRequest(ctx context.Context, cp dto.MakePaymentRequest) (dto.PaymentRequestResponse, error)
	GetSession(ctx context.Context, sessionRequest dto.GetSessionRequest) (dto.AuthResponse, error)
	GetReceiptUsingToken(ctx context.Context, token string) (dto.MakePaymentResponse, error)
	CreateNewSubUser(ctx context.Context, nuser dto.NewUserRequest) (dto.NewUserRequest, error)
	GetReceiptUsingFilters(ctx context.Context, receipt dto.ReceiptFilter) ([]dto.MakePaymentResponse, error)
	GetTransactionStatics(ctx context.Context) (constants.TransactionStatusResponse, error)
	GetTransactionByTransactionType(ctx context.Context, filter dto.GetRransactionByTransactionTypeRequest) ([]dto.MakePaymentResponse, error)
	Token(ctx context.Context, code string) (dto.AccessToken, error)
	Profile(ctx context.Context, userID string) (dto.FusionUser, error)
}
