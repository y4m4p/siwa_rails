# SIWA Rails
This is a sample application includes a SIWA backend process using Ruby on Rails.

## Dependencies
||version|
|:--|:--|
|Ruby|2.6.3|

## Setup
### Install dependencies
```shell
$ bundle install --path vendor/bundle
```

### Set Environment Value
```shell
$ cp .env/sample .env
```

### Startup application
```shell
$ bundle exec rails s
```

## Endpoint Specification
POST `/auth/apple`

|params|type|required?|explanation|sample|
|:--|:--|:--|:--|:--|
|name|String|false|name for the enduser|"y4m4p"|
|authorization_code|String|true|code used for retrieving the enduser's id_token directly from Apple|"xxxx.0.yyyy.zzzz"|
|id_token|String|true|JWT token from the client|"aaa.bbb.ccc"|

### sample with curl
```shell
$ curl -X POST -H "Content-Type:application/json"\
  -d '{"name": "y4m4p", "authorization_code": "xxxx.0.yyyy.zzzz", "id_token": "aaa.bbb.ccc"}'\
  http://localhost:3000/auth/apple
 
=> decoded id_token
```

## Flow diagram
![siwaflow](https://user-images.githubusercontent.com/12812915/77566809-854c9980-6f09-11ea-99e4-8857c648309a.png)

## Core / brief explanation
The core processing for SIWA is written inside the following file.  
[`app/services/apple/sign_in_with_apple_service.rb`](https://github.com/y4m4p/siwa_rails/blob/master/app/services/apple/sign_in_with_apple_service.rb)

This file processes the `authorization_code` and `id_token (from client app)` in the following order.

1. Verify that the hashed `authorization_code` value is equal with decoded `id_token (from client app)`'s `c_hash` value. This step is specified in https://openid.net/specs/openid-connect-core-1_0.html#CodeValidation
2. Request the enduser's `id_token` directly from Apple using the `authorization_code` by sending the code to `https://appleid.apple.com/auth/token` with the specially crafted [client_secret]() values.
3. Retrieve Apple's public key. This public key is used to decrypt the `id_token (from Apple)` requested in step 2.
4. Verify the `id_token (from client app)`'s attribute values with `id_token (from Apple)`. If any of the value is incorrect or missing, the request should be disregarded. If all value was correct, return the **decoded** `id_token (from client app)`. 

## Real world application usage tips
1. This sample application only returns the `payload (id_token returned from Apple)` from the authentication endpoint.
Usually for most backend application for iOS app clients, the endpoint would return some form of `access_token` or simply an `user` object to the client.

2. If you are concerned that the endpoint is receiving a raw `id_token`, the client and server should have some form of encryption/decryption scheme for that value.

## References
(Disclaimer: None of these are my work)
For more informations about how the authorization step works, the following blog post might be useful.  
https://sarunw.com/posts/sign-in-with-apple-1/

For how to gain values for the environment values, the following blog post might be useful.  
https://medium.com/identity-beyond-borders/how-to-configure-sign-in-with-apple-77c61e336003
