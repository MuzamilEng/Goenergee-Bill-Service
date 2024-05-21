package initiator

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/paymax2022/Goenergee-Bill-Service/internal/handler/middleware"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func Initiate() {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatal("unable to start logger")
	}
	configName := "config"
	if os.Getenv("CONFIG_NAME") != "" {
		configName = os.Getenv("CONFIG_NAME")
	}

	logger.Info("initializing config")
	InitConfig(configName, "config", logger)
	logger.Info("config initialization complited")

	logger.Info("initializing database")
	db := InitDB(viper.GetString("database.url"), logger)
	logger.Info("database initialized")

	logger.Info("initializing persistence ")
	persistancedb := InitPersistence(db, *logger)
	logger.Info("peristence layer initialized")

	logger.Info("initializing module")
	module := InitModule(logger, persistancedb)
	logger.Info("modules initialized")

	logger.Info("initializing handler")
	handler := InitHandler(module, *logger)
	logger.Info("handler initialized")

	logger.Info("initializing server ")
	server := gin.New()
	server.Use(middleware.CORS())
	server.Use(middleware.GinLogger(*logger))
	server.Use(middleware.ErrorHandler())
	// Adding CORS middleware

	grp := server.Group("/api")
	InitRouting(grp, *logger, handler)
	logger.Info("router initialized")

	logger.Info("initializing  http server ")
	srv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", viper.GetString("app.host"), viper.GetInt("app.port")),
		Handler:           server,
		ReadHeaderTimeout: viper.GetDuration("app.timeout"),
	}
	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT)
		<-sigint
		if err := srv.Shutdown(context.Background()); err != nil {
			log.Fatalf("HTTP server Shutdown: %v", err)
		} else {
			close(idleConnsClosed)
		}
	}()
	err = srv.ListenAndServe()
	if err == http.ErrServerClosed {
		select {
		case <-idleConnsClosed:
			logger.Info("HTTP server closed via idle connections.")
		default:
			logger.Fatal("HTTP server closed unexpectedly.")
		}
	} else if err != nil {
		logger.Fatal(fmt.Sprintf("Could not start HTTP server: %s", err))
	}

}
