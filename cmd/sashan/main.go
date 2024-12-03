package main

import (
	"fmt"
	"net/http"
	"os"
	"sashan/internal/constants"
	"sashan/internal/db"
	"sashan/internal/routes"

	"github.com/rs/zerolog/log"

	"github.com/rs/zerolog"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Info().Msg("Sashan program initiated")
	router := routes.InitializeRoutes()

	uri := constants.MONGODB_URI
	db.Connect(uri)
	defer db.Disconnect()

	port := ":8080"
	log.Info().Msg(fmt.Sprintf("Server is running on http://localhost%v", port))
	if err := http.ListenAndServe(port, router); err != nil {
		log.Error().Msg(fmt.Sprintf("Unable to start server : %v", err))
	}
}
