**clinet_http**
This code runs on the client side and sends a HTTP request to the server, the HTTP request also containes a token which the server reads.

**server.c**
It creates a web server on the given ip. When a client wants to connect to the server, it has to provide the token, which will be checked, and the connection is upgraded to websocket connection only if the token is correct.

**client_ws.c**
Client which can connect to the web server using the token.


*Clients and run conditions for this project were tested on [Postman](https://www.postman.com/).*
