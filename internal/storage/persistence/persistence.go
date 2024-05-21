package persistence

import (
	"context"

	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants/model/dto"
	"go.mongodb.org/mongo-driver/bson"
)

type User interface {
	SaveTrasnaction(ctx context.Context, transaction dto.Transactions) error
	GetPassword(ctx context.Context) (string, error)
	SaveVendorPassword(ctx context.Context, password string) error
	GetVendorTransactions(ctx context.Context, transactions dto.VendorTransactionRequest) ([]dto.Transactions, error)
	GetShiftEnequiries(ctx context.Context, transactions dto.ShiftEnquiriesRequest) ([]dto.ShiftEnquiriesResponse, error)
	GetPaymentRequestByReferencID(ctx context.Context, refID string) (dto.MakePaymentRequest, error)
	UpdateTransaction(ctx context.Context, transaction dto.Transactions) error
	SaveUser(ctx context.Context, usr dto.NewUserRequest) error
	GetUserByEmail(ctx context.Context, email string) (dto.NewUserRequest, error)
	GetCodeUserUsingEmail(ctx context.Context, email string) (string, error)
	GetCommission(ctx context.Context) (float64, error)
	GetReceiptUsingToken(ctx context.Context, token string) (dto.MakePaymentResponse, error)
	GetReceiptUsingFilters(ctx context.Context, filter bson.M, pageNum, pageSize int) ([]dto.MakePaymentResponse, error)
	CountTransactionByStatus(ctx context.Context, status string) (int64, error)
}
