package user

import (
	"net/http"

	"github.com/paymax2022/Goenergee-Bill-Service/internal/glue/routing"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/handler"
	"github.com/paymax2022/Goenergee-Bill-Service/internal/handler/middleware"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func Init(
	grp *gin.RouterGroup,
	log zap.Logger,
	user handler.User,

) {
	userRoute := []routing.Route{
		{
			Method:     http.MethodPost,
			Path:       "/user",
			Handler:    user.CreateUser,
			Middleware: []gin.HandlerFunc{},
			Domains:    []string{"v1"},
		}, {
			Method:  http.MethodPatch,
			Path:    "/user",
			Handler: user.ModifyUser,
			Middleware: []gin.HandlerFunc{
				middleware.AuthMiddlewAre(),
			},
			Domains: []string{"v1"},
		}, {
			Method:  http.MethodPost,
			Path:    "/user/password/validate",
			Handler: user.ValidatePassword,
			Middleware: []gin.HandlerFunc{
				middleware.AuthMiddlewAre(),
			},
			Domains: []string{"v1"},
		},
		{
			Method:  http.MethodPatch,
			Path:    "/user/password",
			Handler: user.ChangePassword,
			Middleware: []gin.HandlerFunc{
				middleware.AuthMiddlewAre(),
			},
			Domains: []string{"v1"},
		},
		{
			Method:  http.MethodPost,
			Path:    "/user/password",
			Handler: user.ForgotPassword,
			Middleware: []gin.HandlerFunc{
				middleware.AuthMiddlewAre(),
			},
			Domains: []string{"v1"},
		}, {
			Method:  http.MethodGet,
			Path:    "/user",
			Handler: user.SearchUsers,
			Middleware: []gin.HandlerFunc{
				middleware.AuthMiddlewAre(),
			},
			Domains: []string{"v1"},
		}, {
			Method:  http.MethodPost,
			Path:    "/customer",
			Handler: user.SearchCustomer,
			Middleware: []gin.HandlerFunc{
				middleware.AuthMiddlewAre(),
			},
			Domains: []string{"v1"},
		}, {
			Method:  http.MethodGet,
			Path:    "/vendor",
			Handler: user.VendorInformation,
			Middleware: []gin.HandlerFunc{
				middleware.AuthMiddlewAre(),
			},
			Domains: []string{"v1"},
		}, {
			Method:  http.MethodPost,
			Path:    "/criteria/type",
			Handler: user.CriteriaType,
			Middleware: []gin.HandlerFunc{
				middleware.AuthMiddlewAre(),
			},
			Domains: []string{"v1"},
		}, {
			Method:  http.MethodPost,
			Path:    "/calculate/price",
			Handler: user.CalculatePrice,
			Middleware: []gin.HandlerFunc{
				middleware.AuthMiddlewAre(),
			},
			Domains: []string{"v1"},
		}, {
			Method:  http.MethodPost,
			Path:    "/make/payment",
			Handler: user.MakePayment,
			Middleware: []gin.HandlerFunc{
				middleware.AuthMiddlewAre(),
			},
			Domains: []string{"v1"},
		}, {
			Method:  http.MethodPost,
			Path:    "/payment/information",
			Handler: user.RetrieveDetailedPaymentInformation,
			Middleware: []gin.HandlerFunc{
				middleware.AuthMiddlewAre(),
			},
			Domains: []string{"v1"},
		}, {
			Method:     http.MethodPost,
			Path:       "/shiftenquiries",
			Handler:    user.ShiftEnquiries,
			Middleware: []gin.HandlerFunc{},
			Domains:    []string{"v1"},
		}, {
			Method:  http.MethodPost,
			Path:    "/customer/enquiries",
			Handler: user.CustomerEnquiries,
			Middleware: []gin.HandlerFunc{
				middleware.AuthMiddlewAre(),
			},
			Domains: []string{"v1"},
		}, {
			Method:     http.MethodPost,
			Path:       "/venodr/transactions",
			Handler:    user.GetVendorTransactions,
			Middleware: []gin.HandlerFunc{},
			Domains:    []string{"v1"},
		}, {
			Method:     http.MethodPost,
			Path:       "/venodr/password",
			Handler:    user.SetVendorPassword,
			Middleware: []gin.HandlerFunc{},
			Domains:    []string{"v1"},
		}, {
			Method:     http.MethodPost,
			Path:       "/verify/payment/:reference",
			Handler:    user.VerifyMakePayment,
			Middleware: []gin.HandlerFunc{},
			Domains:    []string{"v1"},
		}, {
			Method:     http.MethodGet,
			Path:       "/payment/:token",
			Handler:    user.GetReceiptUsingToken,
			Middleware: []gin.HandlerFunc{},
			Domains:    []string{"v1"},
		}, {
			Method:     http.MethodPost,
			Path:       "/sub/vendor",
			Handler:    user.CreateNewSubUser,
			Middleware: []gin.HandlerFunc{},
			Domains:    []string{"v1"},
		}, {
			Method:     http.MethodPost,
			Path:       "/customer/receipt",
			Handler:    user.GetReceiptUsingFilters,
			Middleware: []gin.HandlerFunc{},
			Domains:    []string{"v1"},
		}, {
			Method:  http.MethodGet,
			Path:    "/vendor/stats",
			Handler: user.GetTransactionStatics,
			Middleware: []gin.HandlerFunc{
				middleware.AuthMiddlewAre(),
			},
			Domains: []string{"v1"},
		}, {
			Method:  http.MethodPost,
			Path:    "/vendor/transactions",
			Handler: user.GetTransactionByTransactionType,
			Middleware: []gin.HandlerFunc{
				middleware.AuthMiddlewAre(),
			},
			Domains: []string{"v1"},
		}, {
			Method:     http.MethodGet,
			Path:       "/token/:code",
			Handler:    user.Token,
			Middleware: []gin.HandlerFunc{},
			Domains:    []string{"v1"},
		}, {
			Method:  http.MethodGet,
			Path:    "/profile",
			Handler: user.Profile,
			Middleware: []gin.HandlerFunc{
				middleware.AuthMiddlewAre(),
			},
			Domains: []string{"v1"},
		},
	}
	routing.RegisterRoute(grp, userRoute, log)

}
