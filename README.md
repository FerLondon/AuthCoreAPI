# AuthCoreAPI

Authentication and Authorization with JWT in ASP.NET Core API

This project is an API developed with ASP.NET Core that provides login, authentication, and authorization functionalities to ensure secure access. Through the login system, users can authenticate with valid credentials. Upon successful authentication, a JWT (JSON Web Token) will be generated and serve as an access token. This token will be used to validate and authorize the user for future requests, ensuring that only authenticated users can access protected resources.

Using JWT allows for a stateless authentication approach, where the token contains all the necessary information to verify the user's identity and permissions, making the API more efficient and secure. The authentication process is quick and secure, with support for user login flows, token expiration control, and session renewal.

Note: Be sure to update the ConnectionStrings with the name "DefaultConnection" in the appsettings.json file to ensure proper database connection and configuration.
