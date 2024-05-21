package goenergy

import (
	"context"
	"fmt"

	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants/errors"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/constants/model/dto"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/storage/persistence"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

type user struct {
	db           *mongo.Collection
	authdb       *mongo.Collection
	userDB       *mongo.Collection
	commissionDB *mongo.Collection
	log          zap.Logger
}

func Init(db, authdb, userdb, commissiondb *mongo.Collection, log zap.Logger) persistence.User {
	return &user{
		db:           db,
		log:          log,
		authdb:       authdb,
		userDB:       userdb,
		commissionDB: commissiondb,
	}
}
func (u *user) SaveTrasnaction(ctx context.Context, transaction dto.Transactions) error {
	_, err := u.db.InsertOne(ctx, transaction)
	if err != nil {
		u.log.Error("Save trasaction", zap.Error(err))
		err = errors.ErrUnableTocreate.Wrap(err, err.Error(), "transaction", transaction)
		return err
	}
	return nil
}
func (u *user) SaveVendorPassword(ctx context.Context, password string) error {
	count, err := u.authdb.CountDocuments(ctx, bson.M{})

	if err != nil {
		err = errors.ErrUnableToUpdate.Wrap(err, err.Error())
		u.log.Error(err.Error())
		return err
	}
	if count > 0 {
		_, err = u.authdb.ReplaceOne(ctx, bson.M{}, bson.M{"password": password})
		if err != nil {
			err = errors.ErrUnableToUpdate.Wrap(err, err.Error())
			u.log.Error(err.Error())
			return err
		}
		return nil
	}

	_, err = u.authdb.InsertOne(ctx, bson.M{"password": password})
	if err != nil {
		err = errors.ErrUnableToUpdate.Wrap(err, err.Error())
		u.log.Error(err.Error())
		return err
	}
	return nil

}
func (u *user) GetPassword(ctx context.Context) (string, error) {
	var auth dto.VendoerRequirement
	err := u.authdb.FindOne(ctx, bson.M{}).Decode(&auth)
	if err != nil {
		err = errors.ErrUnableToGet.Wrap(err, err.Error())
		u.log.Error(err.Error())
		return "", err
	}
	return auth.Password, nil

}
func (c *user) GetVendorTransactions(ctx context.Context, transactions dto.VendorTransactionRequest) ([]dto.Transactions, error) {
	var trans []dto.Transactions
	filter := bson.M{
		"date": bson.M{
			"$gte": transactions.DateFrom,
			"$lte": transactions.DateTo,
		},
	}
	result, err := c.db.Find(ctx, filter)
	if err != nil {
		err = errors.ErrUnableToGet.Wrap(err, err.Error())
		c.log.Error(err.Error(), zap.Any("request", transactions))
		return []dto.Transactions{}, err
	}
	for result.Next(ctx) {
		var elem dto.Transactions
		err := result.Decode(&elem)
		if err != nil {
			c.log.Error(fmt.Sprintf("%v not found: %v", "transactions", err), zap.Any("request", transactions))
			continue
		}
		trans = append(trans, elem)
	}
	return trans, nil
}
func (c *user) GetShiftEnequiries(ctx context.Context, transactions dto.ShiftEnquiriesRequest) ([]dto.ShiftEnquiriesResponse, error) {
	var trans []dto.ShiftEnquiriesResponse
	filter := bson.M{
		"date": bson.M{
			"$gte": transactions.PaymentDate,
			"$lte": transactions.PaymentDateTo,
		},
		"codUser": transactions.CodUserShift,
	}
	result, err := c.db.Find(ctx, filter)
	if err != nil {
		err = errors.ErrUnableToGet.Wrap(err, err.Error())
		c.log.Error(err.Error(), zap.Any("request", transactions))
		return []dto.ShiftEnquiriesResponse{}, err
	}
	for result.Next(ctx) {
		var elem dto.ShiftEnquiriesResponse
		err := result.Decode(&elem)
		if err != nil {
			c.log.Error(fmt.Sprintf("%v not found: %v", "transactions", err), zap.Any("request", transactions))
			continue
		}
		trans = append(trans, elem)
	}
	return trans, nil
}
func (c *user) GetPaymentRequestByReferencID(ctx context.Context, refID string) (dto.MakePaymentRequest, error) {
	var mpr dto.MakePaymentRequest
	if err := c.db.FindOne(ctx, bson.M{"reference": refID}).Decode(&mpr); err != nil {
		err = errors.ErrUnableToGet.Wrap(err, err.Error())
		c.log.Error(err.Error())
		return dto.MakePaymentRequest{}, err
	}
	return mpr, nil
}

func (u *user) UpdateTransaction(ctx context.Context, transaction dto.Transactions) error {

	filter := bson.M{"_id": transaction.ID}
	updates := bson.M{
		"codUser":           transaction.CodUser,
		"account":           transaction.Account,
		"debtPayment":       transaction.DebtPayment,
		"accountBalance":    transaction.AccountBalance,
		"unitsPayment":      transaction.UnitsPayment,
		"units":             transaction.Units,
		"unitsType":         transaction.UnitsType,
		"paymentDate":       transaction.PaymentDate,
		"receipt":           transaction.Receipt,
		"customerName":      transaction.CustomerName,
		"tariffDescription": transaction.TariffDescription,
		"unitsTopUp":        transaction.UnitsTopUp,
		"comment":           transaction.Comment,
		"listtoken":         transaction.Listtoken,
		"keyDataSGC":        transaction.KeyDataSGC,
		"keyDataTI":         transaction.KeyDataTI,
		"keyDataKRN":        transaction.KeyDataKRN,
		"requestID":         transaction.RequestID,
		"mapUnits":          transaction.MapUnits,
		"mapAmount":         transaction.MapAmount,
		"mapTokens":         transaction.MapTokens,
		"kctTokens":         transaction.KctTokens,
		"status":            transaction.Status,
	}
	_, err := u.db.UpdateOne(ctx, filter, bson.M{"$set": updates})
	if err != nil {
		err = errors.ErrUnableToUpdate.Wrap(err, err.Error())
		u.log.Error(err.Error())
		return err
	}
	return nil
}
func (u *user) SaveUser(ctx context.Context, usr dto.NewUserRequest) error {
	_, err := u.userDB.InsertOne(ctx, usr)
	if err != nil {
		u.log.Error("Save trasaction", zap.Error(err))
		err = errors.ErrUnableTocreate.Wrap(err, err.Error(), "user", usr)
		return err
	}
	return nil
}
func (u *user) GetUserByEmail(ctx context.Context, email string) (dto.NewUserRequest, error) {
	ur := dto.NewUserRequest{}
	err := u.userDB.FindOne(ctx, bson.M{"email": email}).Decode(&ur)
	if err != nil && err != mongo.ErrNoDocuments {
		u.log.Error("Save trasaction", zap.Error(err))
		err = errors.ErrUnableTocreate.Wrap(err, err.Error(), "email ", email)
		return dto.NewUserRequest{}, err
	}
	return ur, nil
}
func (u *user) GetCodeUserUsingEmail(ctx context.Context, email string) (string, error) {
	var nuser dto.NewUserRequest
	if err := u.userDB.FindOne(ctx, bson.M{"email": email}).Decode(&nuser); err != nil {
		u.log.Error("unable to get user using email ", zap.Error(err), zap.Any("email", email))
		err = errors.ErrUnableToGet.Wrap(err, err.Error(), "email ", email)
		return "", err
	}
	return nuser.CodNewUser, nil

}
func (u *user) GetCommission(ctx context.Context) (float64, error) {
	var comm dto.Commission
	if err := u.commissionDB.FindOne(ctx, bson.M{}).Decode(&comm); err != nil {
		u.log.Error("unable to get commission ", zap.Error(err))
		err = errors.ErrUnableToGet.Wrap(err, err.Error())
		return 0, err
	}
	return comm.Commission, nil
}
func (u *user) GetReceiptUsingToken(ctx context.Context, token string) (dto.MakePaymentResponse, error) {
	var receipt dto.MakePaymentResponse
	filter := bson.M{"listtoken": bson.M{"$in": []string{token}}}
	err := u.db.FindOne(ctx, filter).Decode(&receipt)
	if err != nil {
		u.log.Error("unable to get receipt ", zap.Error(err))
		err = errors.ErrUnableToGet.Wrap(err, err.Error())
		return dto.MakePaymentResponse{}, err
	}
	return receipt, nil
}
func (u *user) GetReceiptUsingFilters(ctx context.Context, filter bson.M, pageNum, pageSize int) ([]dto.MakePaymentResponse, error) {
	var receipts []dto.MakePaymentResponse
	skip := (pageNum - 1) * pageSize
	opts := options.Find().SetSkip(int64(skip)).SetLimit(int64(pageSize))
	result, err := u.db.Find(ctx, filter, opts)
	if err != nil {
		u.log.Error("unable to get receipt ", zap.Error(err))
		err = errors.ErrUnableToGet.Wrap(err, err.Error())
		return []dto.MakePaymentResponse{}, err
	}

	for result.Next(ctx) {
		var receipt dto.MakePaymentResponse
		if err := result.Decode(&receipt); err != nil {
			u.log.Error("error decoding receipts", zap.Error(err))
			err = errors.ErrUnableToUpdate.Wrap(err, err.Error(), zap.Any("filter", filter))
			return nil, err
		}
		receipts = append(receipts, receipt)
	}

	return receipts, nil
}
func (u *user) CountTransactionByStatus(ctx context.Context, status string) (int64, error) {
	count, err := u.db.CountDocuments(ctx, bson.M{"status": status})
	if err != nil && err != mongo.ErrNilDocument {
		u.log.Error("unable to count transaction by status", zap.Error(err))
		err = errors.ErrUnableToGet.Wrap(err, err.Error(), zap.Any("status", status))
		return 0, err
	}
	return count, nil
}
