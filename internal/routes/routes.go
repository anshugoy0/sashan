package routes

// Package routes handles all the routing logic for the application

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sashan/internal/auth"
	"sashan/internal/constants"
	"sashan/internal/db"
	"sashan/internal/schema"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	LIKE_ROUTE     = "/like"
	UNLIKE_ROUTE   = "/unlike"
	FOLLOW_ROUTE   = "/follow"
	UNFOLLOW_ROUTE = "/unfollow"
)

func InitializeRoutes() *mux.Router {
	router := mux.NewRouter()

	router.HandleFunc("/", homeHandler).Methods("GET")
	router.HandleFunc("/signin", signinHandler).Methods("POST")
	router.HandleFunc("/signup", signupHandler).Methods("POST")

	router.Handle("/post", JwtAuthMiddleware(http.HandlerFunc(postHandler))).Methods("POST", "GET", "DELETE", "PATCH")

	router.Handle(LIKE_ROUTE, JwtAuthMiddleware(http.HandlerFunc(likeHandler))).Methods("POST")
	router.Handle(UNLIKE_ROUTE, JwtAuthMiddleware(http.HandlerFunc(likeHandler))).Methods("POST")

	router.Handle(FOLLOW_ROUTE, JwtAuthMiddleware(http.HandlerFunc(followHandler))).Methods("POST")
	router.Handle(UNFOLLOW_ROUTE, JwtAuthMiddleware(http.HandlerFunc(followHandler))).Methods("POST")

	router.Handle("/feed", JwtAuthMiddleware(http.HandlerFunc(feedHandler))).Methods("GET")
	router.Handle("/message", JwtAuthMiddleware(http.HandlerFunc(handleMessages)))

	return router
}

func JwtAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
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

	collection := db.GetCollection(constants.MAIN_DATABASE, constants.USERS_COLLECTION)
	usr, err := db.GetUser(collection, username, password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	token, err := auth.GenerateJWT(username)
	if err != nil {
		fmt.Println(err.Error())
		http.Error(w, "unable to signin", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token, "msg": fmt.Sprintf("Signed in successfully to " + usr["username"].(string))})
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	username := query.Get("username")
	password := query.Get("password")
	dob := query.Get("dob")

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
		http.Error(w, err.Error(), http.StatusConflict)
	} else {
		w.Write([]byte("signup successful for user " + username))
	}
}

func postHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value("username").(string)

	if !ok {
		http.Error(w, "failed to post", http.StatusInternalServerError)
		return
	}

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

		parent_post_objid, err := primitive.ObjectIDFromHex(body.Parentpost)

		if parent_post_objid.IsZero() {
			fmt.Println("There is no parent of the post")
		} else if err != nil {
			http.Error(w, "incorrect parent post id", http.StatusBadRequest)
			return
		}

		//create object to push to DB
		post_id := primitive.NewObjectID()
		post := schema.Post{
			ID:         post_id,
			Username:   username,
			Text:       body.Text,
			Timestamp:  time.Now().UTC(),
			Likes:      0,
			Childposts: []primitive.ObjectID{},
			Parentpost: parent_post_objid,
		}

		bsondata, err := bson.Marshal(post)
		if err != nil {
			http.Error(w, "unable to parse post, err: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var primitive_post primitive.M
		err = bson.Unmarshal(bsondata, &primitive_post)
		if err != nil {
			http.Error(w, "invalid input", http.StatusBadRequest)
			return
		}

		// Push post to DB
		err = db.CreateDocument(collection, primitive_post)
		if err != nil {
			http.Error(w, "failed to create post", http.StatusInternalServerError)
			return
		}

		if parent_post_objid.IsZero() {
			w.Write([]byte("New post created successfully"))
			return
		}

		// Update parent post
		child_update := bson.M{
			"$push": bson.M{
				"cposts": post_id,
			},
		}

		filter := bson.M{
			"_id": parent_post_objid,
		}

		result, err := db.UpdateDocument(collection, filter, child_update)

		if err != nil {
			http.Error(w, "unable to add post", http.StatusInternalServerError)

			result_delete, err := db.DeleteDocument(collection, bson.M{"_id": post_id})
			if err != nil {
				fmt.Printf("Unable to revert post with id %v\n", post_id)
			} else if result_delete.DeletedCount == 0 {
				fmt.Println("Post is not deleted")
			} else {
				fmt.Printf("Post with ID %v got deleted\n", post_id)
			}

			return
		} else if result.ModifiedCount == 0 {
			http.Error(w, "nothing got modified", http.StatusInternalServerError)
		} else {
			w.Write([]byte("Subpost created successfully"))
		}

	} else if r.Method == "GET" {
		query := r.URL.Query()

		if query.Has("username") {
			username := query.Get("username")
			filter := bson.M{
				"username": username,
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
				http.Error(w, "unable to get post", http.StatusInternalServerError)
			} else {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(posts)
			}
		} else if query.Has("postid") {
			id := query.Get("postid")
			objId, err := primitive.ObjectIDFromHex(id)
			if err != nil {
				http.Error(w, "incorrect id", http.StatusBadRequest)
				return
			}

			filter := bson.M{
				"_id": objId,
			}

			post, err := db.GetDocument(collection, filter)

			if err != nil {
				http.Error(w, "unable to fetch post", http.StatusInternalServerError)
			} else {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(post)
			}
		} else {
			http.Error(w, "unable to get user, provide username or id", http.StatusBadRequest)
		}

	} else if r.Method == "DELETE" {
		query := r.URL.Query()
		id := query.Get("postid")

		objId, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			http.Error(w, "incorrect id provided", http.StatusBadRequest)
			return
		}

		filter := bson.M{
			"_id": objId,
		}

		result, err := db.DeleteDocument(collection, filter)

		if err != nil {
			http.Error(w, "unable to delete", http.StatusInternalServerError)
		} else if result != nil && result.DeletedCount == 0 {
			http.Error(w, "nothing got deleted", http.StatusBadRequest)
		} else {
			w.Write([]byte("Successfully deleted"))
		}
	} else if r.Method == "PATCH" {
		query := r.URL.Query()
		id := query.Get("postid")
		var body bson.M
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			http.Error(w, "check request parameters", http.StatusBadRequest)
			return
		}

		objId, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			http.Error(w, "incorrect id provided", http.StatusBadRequest)
			return
		}

		filter := bson.M{
			"_id": objId,
		}

		text, ok := body["Text"]
		if !ok {
			http.Error(w, "unable to read the text", http.StatusBadRequest)
			return
		}

		update := bson.M{
			"$set": bson.M{
				"text": text,
			},
		}

		result, err := db.UpdateDocument(collection, filter, update)
		if err != nil {
			http.Error(w, "unable to update post", http.StatusInternalServerError)
			return
		} else if result.ModifiedCount == 0 {
			http.Error(w, "nothing got modified", http.StatusInternalServerError)
		} else {
			w.Write([]byte("Modified successfully"))
		}
	}
}

func likeHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Retrieve all request information
	query := r.URL.Query()
	postid := query.Get("postid")

	objid, err := primitive.ObjectIDFromHex(postid) // Convert to useful form
	if err != nil {
		http.Error(w, "invalid post id", http.StatusBadRequest)
		return
	}

	username, ok := r.Context().Value("username").(string)
	if !ok {
		http.Error(w, "failed to post", http.StatusInternalServerError)
		return
	}

	post_collection := db.GetCollection(constants.MAIN_DATABASE, constants.POSTS_COLLECTION)
	user_collection := db.GetCollection(constants.MAIN_DATABASE, constants.USERS_COLLECTION)

	// Check post like status
	user_filter := bson.M{
		"username": username,
	}

	user, err := db.GetDocument(user_collection, user_filter)
	if err != nil {
		http.Error(w, "unable to find user", http.StatusInternalServerError)
		return
	}

	var User schema.User
	user_bytes, _ := bson.Marshal(user)
	err = bson.Unmarshal(user_bytes, &User)
	if err != nil {
		fmt.Printf("Unable to parse user info: %v\n", err)
		http.Error(w, "unable to like post", http.StatusInternalServerError)
		return
	}

	isLiked := false
	if len(User.Interactions.LikedPosts) != 0 {
		likedposts := User.Interactions.LikedPosts
		for _, s := range likedposts {
			if s == objid {
				isLiked = true
			}
		}
	} else {
		fmt.Println("Not liked")
	}

	var update_post bson.M
	var update_user bson.M
	if path == LIKE_ROUTE {
		if isLiked {
			w.Write([]byte("Post already liked"))
			return
		}
		update_post = bson.M{
			"$inc": bson.M{
				"likes": 1,
			},
		}
		update_user = bson.M{
			"$push": bson.M{
				"interactions.likedposts": objid,
			},
		}
	} else if path == UNLIKE_ROUTE {
		if !isLiked {
			w.Write([]byte("Post already unliked"))
			return
		}
		update_post = bson.M{
			"$inc": bson.M{
				"likes": -1,
			},
		}
		update_user = bson.M{
			"$pull": bson.M{
				"interactions.likedposts": objid,
			},
		}
	}

	// Update the post likes info
	filter_post := bson.M{
		"_id": objid,
	}

	client := db.GetClient()
	session, err := client.StartSession()
	if err != nil {
		log.Fatal(err)
	}

	defer session.EndSession(context.TODO())
	err = session.StartTransaction()
	if err != nil {
		log.Fatal(err)
	}

	_, err = post_collection.UpdateOne(context.TODO(), filter_post, update_post)
	if err != nil {
		session.AbortTransaction(context.TODO())
		log.Fatal(err)
	}

	// Update the user interaction info
	_, err = user_collection.UpdateOne(context.TODO(), user_filter, update_user)
	if err != nil {
		session.AbortTransaction(context.TODO())
		log.Fatal(err)
	}

	err = session.CommitTransaction(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	if path == LIKE_ROUTE {
		w.Write([]byte("Liked successfully"))
	} else if path == UNLIKE_ROUTE {
		w.Write([]byte("Unliked successfully"))
	}
}

func followHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	follower_username, ok := r.Context().Value("username").(string)
	followed_username := query.Get("username")

	if !ok {
		http.Error(w, "failed to follow", http.StatusInternalServerError)
		return
	}

	// Check if trying to follow/unfollow self
	if follower_username == followed_username {
		http.Error(w, "cannot follow/unfollow yourself", http.StatusBadRequest)
		return
	}

	// Check if followed user exists
	collection := db.GetCollection(constants.MAIN_DATABASE, constants.USERS_COLLECTION)
	var followedUser schema.User
	err := collection.FindOne(context.TODO(), bson.M{"username": followed_username}).Decode(&followedUser)
	if err != nil {
		fmt.Printf("Error is %v\n", err)
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	filter_follower := bson.M{
		"username": follower_username,
	}

	filter_followed := bson.M{
		"username": followed_username,
	}

	var update_follower bson.M
	var update_followed bson.M

	if r.URL.Path == FOLLOW_ROUTE {
		update_follower = bson.M{
			"$addToSet": bson.M{
				"following": followed_username,
			},
		}

		update_followed = bson.M{
			"$addToSet": bson.M{
				"followers": follower_username,
			},
		}
	} else if r.URL.Path == UNFOLLOW_ROUTE {
		update_follower = bson.M{
			"$pull": bson.M{
				"following": followed_username,
			},
		}

		update_followed = bson.M{
			"$pull": bson.M{
				"followers": follower_username,
			},
		}
	} else {
		http.Error(w, "invalid operation", http.StatusBadRequest)
		return
	}

	client := db.GetClient()

	session, err := client.StartSession()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		http.Error(w, "failed to follow", http.StatusInternalServerError)
		return
	}
	defer session.EndSession(context.TODO())

	err = session.StartTransaction()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		http.Error(w, "failed to follow", http.StatusInternalServerError)
		return
	}

	_, err = collection.UpdateOne(context.TODO(), filter_follower, update_follower)
	if err != nil {
		session.AbortTransaction(context.TODO())
		fmt.Printf("Error: %v\n", err)
		http.Error(w, "failed to follow", http.StatusInternalServerError)
		return
	}

	_, err = collection.UpdateOne(context.TODO(), filter_followed, update_followed)
	if err != nil {
		session.AbortTransaction(context.TODO())
		fmt.Printf("Error: %v\n", err)
		http.Error(w, "failed to follow", http.StatusInternalServerError)
		return
	}

	err = session.CommitTransaction(context.TODO())
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		http.Error(w, "failed to follow", http.StatusInternalServerError)
		return
	}

	if r.URL.Path == FOLLOW_ROUTE {
		w.Write([]byte("Followed successfully"))
	} else {
		w.Write([]byte("Unfollowed successfully"))
	}
}

func feedHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := r.Context().Value("username").(string)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("failed to get feed"))
		return
	}

	users_collection := db.GetCollection(constants.MAIN_DATABASE, constants.USERS_COLLECTION)
	post_collection := db.GetCollection(constants.MAIN_DATABASE, constants.POSTS_COLLECTION)

	filter := bson.M{
		"username": username,
	}

	userinfo, err := db.GetDocument(users_collection, filter)
	if err != nil {
		http.Error(w, "failed to get feed", http.StatusInternalServerError)
		return
	}

	var User schema.User
	user_byte, _ := bson.Marshal(userinfo)
	err = bson.Unmarshal(user_byte, &User)
	if err != nil {
		fmt.Printf("Unable to parse user info: %v\n", err)
		http.Error(w, "unable to get feed", http.StatusInternalServerError)
		return
	}
	yesterday := time.Now().UTC().Add(-24 * time.Hour)

	posts := []map[string]interface{}{}
	following := User.Following
	for _, user_followed := range following {
		filter := bson.M{
			"username": user_followed,
			"timestamp": bson.M{
				"$gte": yesterday,
			},
		}
		posts_primitive, err := db.GetDocuments(post_collection, filter)
		if err != nil {
			fmt.Printf("Error getting post for %v, error: %v\n", user_followed, err)
			continue
		}

		for _, post_primitive := range posts_primitive {
			post_map := make(map[string]interface{})
			for _, elem := range post_primitive {
				post_map[elem.Key] = elem.Value
			}
			posts = append(posts, post_map)
		}
	}

	if len(posts) == 0 {
		http.Error(w, "no posts fetched", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(posts)
}

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

var clients = make(map[string]*websocket.Conn)

func handleMessages(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("Error while upgrading connection:", err)
		return
	}
	defer conn.Close()

	username, ok := r.Context().Value("username").(string)
	if !ok {
		fmt.Println("No username provided in JWT")
		return
	}
	clients[username] = conn

	for {
		_, msg, err := conn.ReadMessage()

		if err != nil {
			fmt.Println("unable to send message")
			break
		}
		var payload schema.Message
		err = json.Unmarshal(msg, &payload)
		if err != nil {
			fmt.Println("Unable to read message")
			break
		}
		message := payload.Message
		receiver := payload.Receiver

		receiver_conn, ok := clients[receiver]
		if !ok {
			fmt.Println("Unable to get connection for receiver")
			break
		}

		message_json := bson.M{
			"sender":  username,
			"message": message,
		}

		err = receiver_conn.WriteJSON(message_json)
		if err != nil {
			receiver_conn.Close()
		}

	}

}
