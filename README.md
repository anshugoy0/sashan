# Sashan

This is the backend server code for a social media application. It's written in Golang and the database of choice is MongoDB

## Steps to run the backend server

#### Step 1: Generate Public and Private Keys
For Key generatetion I am using EC 256 algorithm
```
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem
```

#### Step 2: Setup environment variables

**SA_PRIVATE_KEY** for private key location \
**SA_PUBLIC_KEY** for  public key location \
**SA_MONGODB_URI** for mongodb server location

example:
```
export SA_PRIVATE_KEY=~/private-key.pem
export SA_PUBLIC_KEY=~/public-key.pem
export SA_MONGODB_URI=mongodb://127.0.0.1:27017
```

#### Step 3: Install dependencies
```
go mod tidy
```

#### Step 4: Finally run the server
```
go run cmd/sashan/main.go
```

## Testing the backend
Import `Sashan.postman_collection.json` in postman to access all supported routes
