package main

import (
	"fmt"
	"log"
	"net/http"
	"sashan/internal/constants"
	"sashan/internal/db"
	"sashan/internal/routes"
)

func main() {

	router := routes.InitializeRoutes()

	uri := constants.MONGODB_URI
	db.Connect(uri)
	defer db.Disconnect()

	port := ":8080"
	fmt.Printf("Server is running on http://localhost%v\n", port)
	if err := http.ListenAndServe(port, router); err != nil {
		log.Fatalf("Unable to start server : %v\n", err)
	}

}
