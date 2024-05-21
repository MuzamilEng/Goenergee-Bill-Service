package constants

type ContestStatus string
type endpoint string

const (
	TOKEN                endpoint = "/token"
	NEWUSER              endpoint = "/venUser/1.0.1/"
	VALIDATEUSER         endpoint = "/venLogin/1.0.1/validatePassword"
	CHANGEUSERPASSWORD   endpoint = "/venLogin/1.0.1/"
	FORGOTUSERPASSWORD   endpoint = "/venLogin/1.0.1/"
	SEARCHUSERS          endpoint = "/venUser/1.0.1/searchUsers"
	VENDORINFORMATION    endpoint = "/venInfoVendor/1.0.1/"
	CRITERIATYPE         endpoint = "/venMeter/1.0.1/criteriaType"
	SEARCHCUSTOMER       endpoint = "/venMeter/1.0.1/"
	CALCUATEPRICE        endpoint = "/venPayment/1.0.1/calculatePayment"
	MAKEPAYMENT          endpoint = "/venPayment/1.0.1/makePayment"
	PAYMENTINFO          endpoint = "/venPayment/1.0.1/paymentInfo"
	VENSHIFTENQUIRIES    endpoint = "/venShiftEnquiries/1.0.1/"
	VENCUSTOMERENQUIRIES endpoint = "/venCustomerEnquiries/1.0.1/"
	VENTRANSACTIONS      endpoint = "/venTransactions/1.0.1/"
	INITIALIZEPAYMENT    endpoint = "/initialize-payment"
	VERIFYPAYMENT        endpoint = "/verify-payment/"
	VERIFYTOKEN          endpoint = "/authmgt/v1/keycloak/validateToken"
)

var PENDING string = "PENDING"
var COMPLETED string = "COMPLETED"
var PAYMENT_SUCCESS string = "success"
var TransactionStatus = []string{"COMPLETED", "PENDING", "FAILED"}

const SERVICETYPE string = "GEO_ENERGY"

type TrasactionStatus struct {
	Status string `json:"status"`
	Count  int64  `json:"count"`
}
type TransactionStatusResponse struct {
	Transactions  []TrasactionStatus `json:"transactions"`
	WalletBalance float64            `json:"wallet_balance"`
}

const CodeType = "MY003"
