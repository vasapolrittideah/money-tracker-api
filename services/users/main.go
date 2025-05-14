package main

import "github.com/vasapolrittideah/money-tracker-api/services/users/server"

func main() {
	httpServer := server.NewHttpServer()
	httpServer.Run()
}
