// This file is to store all the functions that interact with MongoDB

package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog/log"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client

func Connect(uri string) {
	var err error
	client, err = mongo.Connect(context.TODO(), options.Client().ApplyURI(uri))

	if err != nil {
		log.Error().Msg(fmt.Sprintf("Failed to connect to database at %v", uri))

	}
}

func GetCollection(database string, colname string) *mongo.Collection {
	return client.Database(database).Collection(colname)
}

func PushUser(collection *mongo.Collection, user bson.M, username string) error {

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
		log.Error().Msg(fmt.Sprintf("Inserted document with ID %v\n", result.InsertedID))
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
		log.Error().Msg(fmt.Sprintf("Unable to disconnect to mongodb, err: %v", err))
	}
}

func CreateDocument(collection *mongo.Collection, doc primitive.M) error {

	result, err := collection.InsertOne(context.TODO(), doc)
	if err != nil {
		return err
	}
	log.Debug().Msg(fmt.Sprintf("document created with ID %v\n", result.InsertedID))
	return nil
}

func GetDocuments(collection *mongo.Collection, filter primitive.M) ([]bson.D, error) {

	cursor, err := collection.Find(context.TODO(), filter)
	if err != nil {
		return nil, err
	}

	var results []bson.D
	for cursor.Next(context.TODO()) {
		var result bson.D
		err := cursor.Decode(&result)
		if err != nil {
			continue
		}
		results = append(results, result)
	}

	return results, nil
}

func GetDocument(collection *mongo.Collection, filter primitive.M) (bson.M, error) {
	var result bson.M
	err := collection.FindOne(context.TODO(), filter).Decode(&result)

	return result, err

}

func DeleteDocument(collection *mongo.Collection, filter primitive.M) (*mongo.DeleteResult, error) {
	result, err := collection.DeleteOne(context.TODO(), filter)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func UpdateDocument(collection *mongo.Collection, filter bson.M, update bson.M) (*mongo.UpdateResult, error) {
	result, err := collection.UpdateOne(context.TODO(), filter, update)

	return result, err
}

func GetClient() *mongo.Client {
	return client
}
