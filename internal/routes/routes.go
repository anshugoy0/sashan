package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sashan/internal/auth"
	"sashan/internal/constants"
	"sashan/internal/db"
	"sashan/internal/user"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func InitializeRoutes() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/", homeHandler).Methods("GET")
	router.HandleFunc("/signin", signinHandler).Methods("POST")
	router.HandleFunc("/signup", signupHandler).Methods("POST")

	return router
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to Sashan"))
}

func signinHandler(w http.ResponseWriter, r *http.Request) {

	query := r.URL.Query()
	username := query.Get("username")
	password := query.Get("password")

	uri := constants.MONGODB_URI
	db.Connect(uri)
	defer db.Disconnect()
	collection := db.GetCollection(constants.MAIN_DATABASE, constants.USERS_COLLECTION)
	usr, err := db.GetUser(collection, username, password)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
	} else {
		token, err := auth.GenerateJWT()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Unable to SignIn"))
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"token": token, "msg": fmt.Sprintf("Signed in successfully to " + usr["username"].(string))})
		}
	}

}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	username := query.Get("username")
	password := query.Get("password")
	dob := query.Get("dob")

	uri := constants.MONGODB_URI
	db.Connect(uri)
	defer db.Disconnect()
	collection := db.GetCollection(constants.MAIN_DATABASE, constants.USERS_COLLECTION)

	user := user.User{
		Username: username,
		Password: password,
		DOB:      dob,
	}

	primitive_user := primitive.D{
		{Key: "username", Value: user.Username},
		{Key: "password", Value: user.Password},
		{Key: "dob", Value: user.DOB},
	}

	err := db.PushUser(collection, primitive_user, username)
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(err.Error()))
	} else {
		w.Write([]byte("signup successful for user " + username))
	}
}
