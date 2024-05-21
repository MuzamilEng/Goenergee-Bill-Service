package dto

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct{}
type APIRequest struct {
	Method  string
	URL     string
	Body    []byte
	Headers map[string]string
}
type APIRequestAccessTokenRequest struct {
	Method  string
	URL     string
	Body    map[string]string
	Headers map[string]string
}
type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type NewUserRequest struct {
	IDVendor   int    `json:"idVendor"`
	CodUser    string `json:"codUser"`
	Name       string `json:"name" validate:"required"`
	CodNewUser string `json:"codNewUser" `
	Email      string `json:"email" validate:"required,email"`
	UserAdmin  bool   `json:"userAdmin"`
	Active     bool   `json:"active"`
	PhoneNo    string `json:"phoneNo"`
}

type UserErro struct {
	Code         string `json:"code"`
	MsgUser      string `json:"msgUser"`
	MsgDeveloper string `json:"msgDeveloper"`
}

type UpdateUserRequest struct {
	IdVendor    int    `json:"idVendor"`
	CodUser     string `json:"codUser"`
	CodUserMod  string `json:"codUserMod"  validate:"required"`
	NewName     string `json:"newName"`
	NewEmail    string `json:"newEmail"`
	UserAdmin   bool   `json:"userAdmin"`
	NewIsActive bool   `json:"newIsActive"`
}

type ValidatePassword struct {
	IdVendor   int    `json:"idVendor"`
	CodUser    string `json:"codUser" validate:"required"`
	CurrentPwd string `json:"currentPwd" validate:"required"`
}
type ErrorResponse struct {
	Code         string `json:"code"`
	MsgUser      string `json:"msgUser"`
	MsgDeveloper string `json:"msgDeveloper"`
}
type ChangePasswordRequest struct {
	IdVendor   int    `json:"idVendor"`
	CodUser    string `json:"codUser" validate:"required"`
	CurrentPwd string `json:"currentPwd" validate:"required"`
	NewPwd     string `json:"newPwd" validate:"required"`
}
type ForgotPassword struct {
	IdVendor int    `json:"idVendor"`
	CodUser  string `json:"codUser" validate:"required"`
}
type SearchUsers struct {
	Name      string `json:"name"`
	CodUser   string `json:"codUser"`
	Email     string `json:"email"`
	UserAdmin int    `json:"userAdmin"`
	Active    int    `json:"active"`
}
type Vendor struct {
	IdVendor int    `json:"idVendor"`
	CodUser  string `json:"codUser" validate:"required" `
}
type VendorInformatinResponse struct {
	IdVendor   string  `json:"idVendor"`
	DescVendor string  `json:"descVendor"`
	District   string  `json:"district"`
	Balance    float64 `json:"balance"`
}

type CriteriaTypeResponse struct {
	CodType string `json:"codType"`
	Type    string `json:"type"`
	Default int    `json:"default"`
}
type SearchCustomerRequest struct {
	IdVendor     int    `json:"idVendor"`
	CodUser      string `json:"codUser" validate:"required"`
	CodType      string `json:"codType" validate:"required"`
	Value        string `json:"value" validate:"required"`
	TotalPayment int    `json:"totalPayment" validate:"required"`
}
type SearchCustomerResponse struct {
	MeterSerial             string  `json:"meterSerial"`
	Account                 int     `json:"account"`
	TariffDescription       string  `json:"tariffDescription"`
	ServiceAddress          string  `json:"serviceAddress"`
	Name                    string  `json:"name"`
	AccountBalance          float64 `json:"accountBalance"`
	IndicatorPrePostAccount int64   `json:"indicatorPrePostAccount"`
}
type CalculatePriceRequest struct {
	IdVendor     int     `json:"idVendor"`
	CodUser      string  `json:"codUser"`
	MeterSerial  string  `json:"meterSerial" `
	Account      string  `json:"account"`
	TotalPayment float64 `json:"totalPayment"`
	DebtPayment  float64 `json:"debtPayment"`
}
type UnitsTopUp struct {
	Concept     string  `json:"concept"`
	Units       float64 `json:"units"`
	ConceptName string  `json:"conceptName"`
	Price       float64 `json:"price"`
	Amount      float64 `json:"amount"`
}
type CalculatePriceResponse struct {
	Account           int          `json:"account"`
	MeterSerial       string       `json:"meterSerial"`
	CustomerName      string       `json:"customerName"`
	TariffDescription string       `json:"tariffDescription"`
	ServiceAddress    string       `json:"serviceAddress"`
	LastPaymentDate   int          `json:"lastPaymentDate"`
	AmountLast        float64      `json:"amountLast"`
	DebtPayment       float64      `json:"debtPayment"`
	PercentageDebt    float64      `json:"percentageDebt"`
	AccountBalance    float64      `json:"accountBalance"`
	UnitsPayment      float64      `json:"unitsPayment"`
	Units             float64      `json:"units"`
	UnitsType         string       `json:"unitsType"`
	UnitsTopUp        []UnitsTopUp `json:"unitsTopUp"`
}

type MakePaymentRequest struct {
	ID                primitive.ObjectID `json:"id" bson:"_id"`
	IdVendor          int                `json:"idVendor" bson:"idVendor"`
	CodUser           string             `json:"codUser" bson:"codUser"`
	MeterSerial       string             `json:"meterSerial" bson:"meterSerial"`
	TotalPayment      float64            `json:"totalPayment" bson:"totalPayment" `
	DebtPayment       float64            `json:"debtPayment" bson:"debtPayment" `
	Account           string             `json:"account" bson:"account"`
	TariffDescription string             `json:"tariffDescription" bson:"tariffDescription" `
	PercentageDebt    float64            `json:"percentageDebt" bson:"percentageDebt" `
	AccountBalance    float64            `json:"accountBalance" bson:"accountBalance"`
	UnitsPayment      float64            `json:"unitsPayment" bson:"unitsPayment" `
	Units             float64            `json:"units" bson:"units"`
	UnitsType         string             `json:"unitsType" bson:"unitsType" `
	Comment           string             `json:"comment" bson:"comment" `
	RequestID         string             `json:"requestID" bson:"requestID"`
	Channel           int                `json:"channel" bson:"channel" validate:"required"`
	AreaCode          int                `json:"areaCode" bson:"areaCode" `
	ServiceCode       int                `json:"serviceCode" bson:"serviceCode" `
	PhoneNo           string             `json:"phoneNo" bson:"phoneNo" `
	Email             string             `json:"email" bson:"email" validate:"required"`
	Status            string             `json:"status" bson:"status"`
}
type MakePaymentResponse struct {
	IdVendor          int          `json:"idVendor"`
	CodUser           string       `json:"codUser"`
	MeterSerial       string       `json:"meterSerial"`
	Account           string       `json:"account"`
	DebtPayment       float64      `json:"debtPayment"`
	TotalPayment      float64      `json:"totalPayment"`
	AccountBalance    float64      `json:"accountBalance"`
	UnitsPayment      float64      `json:"unitsPayment"`
	Units             float64      `json:"units"`
	UnitsType         string       `json:"unitsType"`
	PaymentDate       int          `json:"paymentDate"`
	Receipt           string       `json:"receipt"`
	CustomerName      string       `json:"customerName"`
	TariffDescription string       `json:"tariffDescription"`
	UnitsTopUp        []UnitsTopUp `json:"unitsTopUp"`
	Comment           string       `json:"comment"`
	Listtoken         []string     `json:"listtoken"`
	KeyDataSGC        int          `json:"keyDataSGC"`
	KeyDataTI         int          `json:"keyDataTI"`
	KeyDataKRN        int          `json:"keyDataKRN"`
	RequestID         string       `json:"requestID"`
	Channel           int          `json:"channel"`
	MapUnits          float64      `json:"mapUnits"`
	MapAmount         float64      `json:"mapAmount"`
	MapTokens         []string     `json:"mapTokens"`
	KctTokens         []string     `json:"kctTokens"`
}
type RetrieveDetailedPaymentInformationRequest struct {
	IdVendor      int    `json:"idVendor"`
	CodUser       string `json:"codUser" validate:"required"`
	TransactionId string `json:"transactionId,omitempty" `
	RequestID     string `json:"requestID" validate:"required"`
}
type RetrieveDetailedPaymentInformationResponse struct {
	IdVendor          int          `json:"idVendor"`
	CodUser           string       `json:"codUser"`
	MeterSerial       string       `json:"meterSerial"`
	Account           string       `json:"account"`
	DebtPayment       float64      `json:"debtPayment"`
	TotalPayment      float64      `json:"totalPayment"`
	AccountBalance    float64      `json:"accountBalance"`
	UnitsPayment      float64      `json:"unitsPayment"`
	Units             float64      `json:"units"`
	UnitsType         string       `json:"unitsType"`
	PaymentDate       int          `json:"paymentDate"`
	Receipt           string       `json:"receipt"`
	CustomerName      string       `json:"customerName"`
	TariffDescription string       `json:"tariffDescription"`
	UnitsTopUp        []UnitsTopUp `json:"unitsTopUp"`
	Comment           string       `json:"comment"`
	Listtoken         []string     `json:"listtoken"`
	KeyDataSGC        int          `json:"keyDataSGC `
	KeyDataTI         int          `json:"keyDataTI"`
	KeyDataKRN        int          `json:"keyDataKRN"`
	RequestID         string       `json:"requestID"`
	Channel           int          `json:"channel"`
	MapUnits          float64      `json:"mapUnits"`
	MapAmount         float64      `json:"mapAmount"`
	MapTokens         []string     `json:"mapTokens"`
	KctTokens         []string     `json:"kctTokens"`
}

type ShiftEnquiriesRequest struct {
	PassWord      string `json:"passWord" validate:"required"`
	CodUserShift  string `json:"codUserShift" validate:"required"`
	PaymentDateTo int    `json:"payment_date_to"`
	PaymentDate   int    `json:"paymentDate" validate:"required"`
}

type ShiftEnquiriesResponse struct {
	IdVendor        int    `json:"idVendor"`
	CodUser         string `json:"codUser"`
	Receipt         string `json:"receipt"`
	CustomerName    string `json:"customerName"`
	Account         string `json:"account"`
	MeterSerial     string `json:"meterSerial"`
	DebtPayment     int    `json:"debtPayment"`
	UnitPayment     int    `json:"unitPayment"`
	TotalAmount     int    `json:"totalAmount"`
	Unit            int    `json:"unit"`
	Unitstype       string `json:"unitstype"`
	TransactionDate int    `json:"transactionDate"`
	RequestID       string `json:"requestID"`
}

type CustomerEnquiriesRequest struct {
	IDVendor    int    `json:"idVendor"`
	CodUser     string `json:"codUser" validate:"required"`
	Receipt     string `json:"receipt" validate:"required"`
	MeterSerial int    `json:"meterSerial"`
	Account     string `json:"account"`
	DateFrom    int    `json:"dateFrom" validate:"required"`
	DateTo      int    `json:"dateTo" validate:"required"`
}

type CustomerEnquiriesResponse struct {
	IdVendor        int     `json:"idVendor"`
	DescVendor      string  `json:"descVendor"`
	NameCashier     string  `json:"nameCashier"`
	CodUser         string  `json:"codUser"`
	DateTransaction string  `json:"dateTransaction"`
	Receipt         string  `json:"receipt"`
	CustomerName    string  `json:"customerName"`
	Account         string  `json:"account"`
	MeterSerial     string  `json:"meterSerial"`
	DebtPayment     float64 `json:"debtPayment"`
	UnitsPayment    float64 `json:"unitsPayment"`
	TotalAmount     float64 `json:"totalAmount"`
	Units           float64 `json:"units"`
	UntisType       string  `json:"untisType"`
	TransactionId   string  `json:"transactionId"`
	RequestID       string  `json:"requestID"`
}

type VendorTransactionRequest struct {
	PassWord string `json:"passWord" validate:"required"`
	DateFrom int    `json:"dateFrom" validate:"required"`
	DateTo   int    `json:"dateTo" validate:"required"`
}
type VendoerRequirement struct {
	Password string `json:"password"`
}

type VendorTransactionResponse struct {
	IdVendor        int      `json:"idVendor"`
	CodUser         string   `json:"codUser"`
	TransactionDate int      `json:"transactionDate"`
	ReceiptNo       string   `json:"receiptNo"`
	DebtPayment     float64  `json:"debtPayment"`
	UnitsPayment    float64  `json:"unitsPayment"`
	TotalAmount     float64  `json:"totalAmount"`
	Units           float64  `json:"units"`
	RequestID       string   `json:"requestID"`
	Listtoken       []string `json:"listtoken"`
	Channel         int      `json:"channel"`
	MeterSerial     string   `json:"meterSerial"`
	Account         int      `json:"account"`
}
type Transactions struct {
	ID                primitive.ObjectID `json:"id" bson:"_id"`
	CodUser           string             `json:"codUser" bson:"codUser"`
	MeterSerial       string             `json:"meterSerial" bson:"meterSerial"`
	Account           string             `json:"account" bson:"account"`
	DebtPayment       float64            `json:"debtPayment" bson:"debtPayment"`
	TotalPayment      float64            `json:"totalPayment" bson:"totalPayment"`
	AccountBalance    float64            `json:"accountBalance" bson:"accountBalance"`
	UnitsPayment      float64            `json:"unitsPayment" bson:"unitsPayment"`
	Units             float64            `json:"units" bson:"units"`
	UnitsType         string             `json:"unitsType" bson:"unitsType"`
	PaymentDate       int                `json:"paymentDate" bson:"paymentDate"`
	Receipt           string             `json:"receipt" bson:"receipt"`
	CustomerName      string             `json:"customerName" bson:"customerName"`
	TariffDescription string             `json:"tariffDescription" bson:"tariffDescription"`
	UnitsTopUp        []UnitsTopUp       `json:"unitsTopUp" bson:"unitsTopUp"`
	Comment           string             `json:"comment" bson:"comment"`
	Listtoken         []string           `json:"listtoken" bson:"listtoken"`
	KeyDataSGC        int                `json:"keyDataSGC" bson:"keyDataSGC"`
	KeyDataTI         int                `json:"keyDataTI" bson:"keyDataTI"`
	KeyDataKRN        int                `json:"keyDataKRN" bson:"keyDataKRN"`
	RequestID         string             `json:"requestID" bson:"requestID"`
	Channel           int                `json:"channel" bson:"channel"`
	MapUnits          float64            `json:"mapUnits" bson:"mapUnits"`
	MapAmount         float64            `json:"mapAmount" bson:"mapAmount"`
	MapTokens         []string           `json:"mapTokens" bson:"mapTokens"`
	KctTokens         []string           `json:"kctTokens" bson:"kctTokens"`
	Date              int64              `json:"date" bson:"date" `
	Status            string             `json:"status" bson:"status"`
	Reference         string             `json:"reference"  bson:"reference"`
	Commission        float64            `json:"commission" bson:"commission"`
	Email             string             `json:"email" bson:"email"`
	Type              string             `json:"type" bson:"type"`
}

type InitializePaymentRequest struct {
	Email       string  `json:"email"`
	Amount      float64 `json:"amount"`
	CallbackURL string  `json:"callback_url"`
	ServiceType string  `json:"serviceType"`
}
type InitPyamentResponseData struct {
	AuthorizationURL string `json:"authorization_url"`
	AccessCode       string `json:"access_code"`
	Reference        string `json:"reference"`
}
type InitPaymentResponse struct {
	Status  bool                    `json:"status"  bson:"status"`
	Message string                  `json:"message" bson:"message"`
	Data    InitPyamentResponseData `json:"data" bson:"data"`
}
type VerificationPaymentData struct {
	Amount float64 `json:"amount"`
	Status string  `json:"status"`
}
type VerficationResponse struct {
	Status  bool                    `json:"status"  bson:"status"`
	Message string                  `json:"message" bson:"message"`
	Data    VerificationPaymentData `json:"data"`
}

type Authh0User struct {
	Email      string `json:"email" validate:"required"`
	Password   string `json:"password" validate:"required"`
	Name       string `json:"name,omitempty" validate:"required"`
	Connection string `json:"connection,omitempty"`
}
type PaymentRequestResponse struct {
	CheckoutURL string  `json:"chackout_url"`
	Transaction string  `json:"transaction"`
	Status      string  `json:"status"`
	Amount      float64 `json:"amount"`
	MeterNumber string  `json:"meter_number"`
	Product     string  `json:"product"`
	Address     string  `json:"address"`
	Name        string  `json:"name"`
	Commission  float64 `json:"commission"`
}
type GetSessionRequest struct {
	Email    string `json:"email"  validate:"required"`
	Password string `json:"password"  validate:"required"`
}

type AuthServiceResponse struct {
	Result struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Active        bool   `json:"active"`
	} `json:"result"`
}
type Token struct {
	AccessToken string `json:"accessToken"`
}
type RegisterToAuth0Reqest struct {
	Name     string `json:"name" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password"`
}
type Commission struct {
	ID         primitive.ObjectID `json:"id" bson:"_id"`
	Commission float64            `json:"commission" bson:"commission"`
}

type ReceiptFilter struct {
	Email      string `json:"email"  validate:"required,email"`
	RequestID  string `json:"request_id"`
	PageNumber int    `json:"page_number"`
	PerPage    int    `json:"per_page"`
}
type GetRransactionByTransactionTypeRequest struct {
	Type       string `json:"type"  validate:"required"`
	PageNumber int    `json:"page_number"`
	PerPage    int    `json:"per_page"`
}

type FusionUser struct {
	Email       string `json:"email,omitempty" validate:"required,email"`
	FirstName   string `json:"first_name,omitempty" validate:"required"`
	LastName    string `json:"last_name,omitempty" validate:"required"`
	MobilePhone string `json:"mobile_phone,omitempty" validate:"required"`
	Password    string `json:"password,omitempty"`
}
type FusionRegistrationResponse struct {
	Token string     `json:"token,omitempty"`
	User  FusionUser `json:"user,omitempty"`
}
type AccessToken struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}
