package schema

type User struct {
	Username string `bson:"title"`
	Password string `bson:"password"`
	DOB      string `bson:"dob"`
}

type Post struct {
	Text     string   `bson:"text"`
	Likes    int      `bson:"likes"`
	Comments []string `bson:"comments"`
}

type PostBody struct {
	Text string `bson:"text"`
}
