package schema

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID         primitive.ObjectID   `bson:"_id"`
	Username   string               `bson:"username"`
	Password   string               `bson:"password"`
	DOB        string               `bson:"dob"`
	LikedPosts []primitive.ObjectID `bson:"likedposts,omitempty"`
	Followers  []string             `bson:"followers,omitempty"`
	Following  []string             `bson:"following,omitempty"`
}

type Post struct {
	ID         primitive.ObjectID   `bson:"_id"`
	Username   string               `bson:"username"`
	Text       string               `bson:"text"`
	Timestamp  time.Time            `bson:"timestamp"`
	Likes      int                  `bson:"likes"`
	Childposts []primitive.ObjectID `bson:"cposts"`
	Parentpost primitive.ObjectID   `bson:"ppost"`
}

type PostBody struct {
	Text       string `json:"text"`
	Parentpost string `json:"parentid"`
}

type Message struct {
	Receiver string `json:"receiver"`
	Message  string `json:"message"`
}
