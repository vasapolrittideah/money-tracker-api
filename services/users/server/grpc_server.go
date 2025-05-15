package server

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/vasapolrittideah/money-tracker-api/services/users/handler"
	"github.com/vasapolrittideah/money-tracker-api/services/users/repository"
	"github.com/vasapolrittideah/money-tracker-api/services/users/service"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/logger"
	"google.golang.org/grpc"
	"gorm.io/gorm"
)

type userGrpcServer struct {
	cfg *config.Config
	db  *gorm.DB
}

func NewUserGrpcServer(cfg *config.Config, db *gorm.DB) *userGrpcServer {
	return &userGrpcServer{cfg: cfg, db: db}
}

func (s *userGrpcServer) Run() {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%v", s.cfg.Server.UserServerGrpcPort))
	if err != nil {
		logger.L.Fatalf("[USERS] Failed to listen: %v", err)
	}

	userGrpcServer := grpc.NewServer()

	userService := service.NewUserService(repository.NewUserRepository(s.db), s.cfg)
	handler.NewUserGrpcHandler(userGrpcServer, userService, s.cfg)

	go func() {
		if err := userGrpcServer.Serve(lis); err != nil {
			logger.L.Fatalf("[USERS] Failed to serve gRPC server: %v", err)
		}
	}()

	logger.L.Infof("[USERS] 🚀 gRPC server started on port %v", s.cfg.Server.UserServerGrpcPort)

	quit := make(chan os.Signal, 1)
	signal.Notify(
		quit,
		os.Interrupt,
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	<-quit
}
