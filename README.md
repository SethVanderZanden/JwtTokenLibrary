# JwtTokenLibrary

This project is a dotnet 6 library created for speeding my implementation of JWT Tokens in my projects. 

It contains JWT Token generation, renewal, validation, grabbing the email and date expiration. It also contains a class to be utilized in the middleware to ensure all tokens are verfied before fully connecting the client with the backend.


### To Do
* Add container to store all paths to be ignored by the middleware that the user can easily alter. i.e api/user/login and api/user/register