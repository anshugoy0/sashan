package user

type User struct {
	Username string `bson:"title"`
	Password string `bson:"password"`
	DOB      string `bson:"dob"`
}
