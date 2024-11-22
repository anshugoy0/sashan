package schema

type User struct {
	Username string `bson:"title"`
	Password string `bson:"password"`
	DOB      string `bson:"dob"`
}

type Post struct {
	Username string    `bson:"username"`
	Text     string    `bson:"text"`
	Likes    int       `bson:"likes"`
	Comments []Comment `bson:"comments"`
}

type Comment struct {
	CUsername   string       `bson:"cusername"`
	Text        string       `bson:"text"`
	Likes       int          `bson:"likes"`
	SubComments []SubComment `bson:"subcomments"`
	Valid       bool         `bson:"valid" default:"true"`
}

type SubComment struct {
	SCUsername string `bson:"scusername"`
	Text       string `bson:"text"`
	Likes      int    `bson:"likes"`
	Valid      bool   `bson:"valid" default:"true"`
}

type PostBody struct {
	Text string `bson:"text"`
}
