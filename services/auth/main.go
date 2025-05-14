package main

import (
	"github.com/vasapolrittideah/money-tracker-api/services/auth/server"
)

func main() {
	httpServer := server.NewHttpServer()
	httpServer.Run()
}
