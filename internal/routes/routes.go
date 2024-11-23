package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sashan/internal/auth"
	"sashan/internal/constants"
	"sashan/internal/db"
	"sashan/internal/schema"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func InitializeRoutes() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/", homeHandler).Methods("GET")
	router.HandleFunc("/signin", signinHandler).Methods("POST")
	router.HandleFunc("/signup", signupHandler).Methods("POST")

	router.Handle("/post", JwtAuthMiddleware(http.HandlerFunc(postHandler))).Methods("POST")
	router.Handle("/post", JwtAuthMiddleware(http.HandlerFunc(postHandler))).Methods("GET")
	router.Handle("/post", JwtAuthMiddleware(http.HandlerFunc(postHandler))).Methods("DELETE")
	router.Handle("/post", JwtAuthMiddleware(http.HandlerFunc(postHandler))).Methods("PATCH")

	return router
}

func JwtAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodECDSA)
			if !ok {
				return nil, http.ErrNotSupported
			}
			secretKey, _ := auth.ParsePublicKey()
			return secretKey, nil
		})

		if err != nil {
			fmt.Println(err)
		}

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Claim Failed", http.StatusInternalServerError)
			return
		}
		username := claims["username"]

		ctx := context.WithValue(r.Context(), "username", username)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
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
		token, err := auth.GenerateJWT(username)
		if err != nil {
			fmt.Println(err.Error())
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

	user := schema.User{
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

func postHandler(w http.ResponseWriter, r *http.Request) {

	username, ok := r.Context().Value("username").(string)

	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("failed to post"))
		return
	}

	// Setup mongodb connection
	uri := constants.MONGODB_URI
	db.Connect(uri)
	defer db.Disconnect()
	collection := db.GetCollection(constants.MAIN_DATABASE, constants.POSTS_COLLECTION)

	if r.Method == "POST" {
		// get the request body
		var body schema.PostBody
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("failed to post"))
			return
		}

		//create object to push to DB
		post := schema.Post{
			Username: username,
			Text:     body.Text,
			Likes:    0,
			Comments: []schema.Comment{},
		}

		bsondata, err := bson.Marshal(post)
		if err != nil {
			fmt.Println("Unable to parse post: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var primitive_post primitive.D
		err = bson.Unmarshal(bsondata, &primitive_post)
		if err != nil {
			fmt.Println("Unable to unmarshal post: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Push to DB
		err = db.CreateDocument(collection, primitive_post)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Failed to create post"))
		} else {
			w.Write([]byte("Post Created Successfully"))
		}
	} else if r.Method == "GET" {

		query := r.URL.Query()

		if query.Has("username") {
			username := query.Get("username")
			filter := bson.D{
				{Key: "username", Value: username},
			}
			posts_primitive, err := db.GetDocuments(collection, filter)
			posts := []map[string]interface{}{}
			for _, post_primitive := range posts_primitive {
				post_map := make(map[string]interface{})
				for _, elem := range post_primitive {
					post_map[elem.Key] = elem.Value
				}
				posts = append(posts, post_map)
			}

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Unable to get post"))
			} else {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(posts)
			}
		} else if query.Has("postid") {
			id := query.Get("postid")
			objId, err := primitive.ObjectIDFromHex(id)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte("Incorrect ID"))
				return
			}

			filter := bson.M{
				"_id": objId,
			}

			post, err := db.GetDocument(collection, filter)

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Unable to fetch post"))
			} else {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(post)
			}
		} else {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Unable to get, provide username of ID"))
		}

	} else if r.Method == "DELETE" {
		query := r.URL.Query()
		id := query.Get("postid")

		objId, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Incorrect ID provided"))
			return
		}

		filter := bson.M{
			"_id": objId,
		}

		result, err := db.DeleteDocument(collection, filter)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Unable to delete"))
		} else if result != nil && result.DeletedCount == 0 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Nothing got deleted"))
		} else {
			w.Write([]byte("Successfully deleted"))
		}
	} else if r.Method == "PATCH" {
		query := r.URL.Query()
		id := query.Get("postid")
		var body bson.M
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Check request parameters"))
			return
		}

		objId, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Incorrect Id provided"))
		}

		filter := bson.M{
			"_id": objId,
		}

		text, ok := body["Text"]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Unable to read the Text"))
		}

		update := bson.M{
			"$set": bson.M{
				"text": text,
			},
		}

		result, err := db.UpdateDocument(collection, filter, update)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Unable to update post"))
			return
		} else if result.ModifiedCount == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Nothing got modified"))
		} else {
			w.Write([]byte("Modified successfully"))
		}

	}
}
