package schema

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	Username string `bson:"title"`
	Password string `bson:"password"`
	DOB      string `bson:"dob"`
}

type Post struct {
	ID         primitive.ObjectID   `bson:"_id"`
	Username   string               `bson:"username"`
	Text       string               `bson:"text"`
	Likes      int                  `bson:"likes"`
	Childposts []primitive.ObjectID `bson:"cposts"`
	Parentpost primitive.ObjectID   `bson:"ppost"`
}

type PostBody struct {
	Text       string `bson:"text"`
	Parentpost string `bson:"ppost,omitempty"`
}
