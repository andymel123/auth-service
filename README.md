# auth-service
OAuth2 in => JWT out 

**> Not production ready yet <**

Goals:
- The service handles authentication with OAuth at Google, Facebook,...
- It issues JWT tokens
- An API to get the Public Key for checking the tokens (available to other services or the API-Gateway)
- The API-Gateway or the resource services just need to read the tokens from the requests and check against the public key of this service
