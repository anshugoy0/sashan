package schema

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	ID           primitive.ObjectID `bson:"_id"`
	Username     string             `bson:"username"`
	Password     string             `bson:"password"`
	DOB          string             `bson:"dob"`
	Interactions Interaction        `bson:"interactions"`
}

type Interaction struct {
	LikedPosts []primitive.ObjectID `bson:"likedposts"`
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
