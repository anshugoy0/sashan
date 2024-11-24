# sashan

For Key generatetion I am using EC 256 algorithm
```
openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
openssl ec -in private-key.pem -pubout -out public-key.pem
```

The repository has some basic routes at this point