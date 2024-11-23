package main

import (
	"fmt"
	"log"
	"net/http"
	"sashan/internal/routes"
)

func main() {

	router := routes.InitializeRoutes()

	port := ":8080"
	fmt.Printf("Server is running on http://localhost%v\n", port)
	if err := http.ListenAndServe(port, router); err != nil {
		log.Fatalf("Unable to start server : %v\n", err)
	}

}
