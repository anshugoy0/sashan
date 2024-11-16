package db

import (
	"context"
	"errors"
	"fmt"
	"log"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client

func Connect(uri string) {
	var err error
	client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(uri))

	if err != nil {
		fmt.Printf("Failed to connect to database at %v", uri)
	}
}

func GetCollection(database string, colname string) *mongo.Collection {
	return client.Database(database).Collection(colname)
}

func PushUser(collection *mongo.Collection, user bson.D, username string) error {

	var result bson.M
	filter := bson.D{
		{Key: "username", Value: username},
	}
	err := collection.FindOne(context.TODO(), filter).Decode(&result)

	if err == mongo.ErrNoDocuments {
		result, err := collection.InsertOne(context.TODO(), user)
		if err != nil {
			return err
		}
		fmt.Printf("Inserted document with ID %v\n", result.InsertedID)
		return nil
	} else if err != nil {
		return err
	} else {
		return fmt.Errorf("username %v already exists", username)
	}
}

func GetUser(collection *mongo.Collection, username string, password string) (bson.M, error) {
	var result bson.M
	filter := bson.D{
		{Key: "username", Value: username},
		{Key: "password", Value: password},
	}
	err := collection.FindOne(context.TODO(), filter).Decode(&result)

	if err == mongo.ErrNoDocuments {
		return nil, errors.New("username or password is incorrect")
	} else if err != nil {
		return nil, err
	} else {
		return result, nil
	}
}

func Disconnect() {
	if err := client.Disconnect(context.TODO()); err != nil {
		log.Fatal(err)
	}
}
