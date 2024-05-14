# JWT Verify Module

# Use Case

I am gonna use this multiple times in my projects and I dont want to reinvent the logic every time.

# License

Project signed under GPLv3 license.

# Installation

`go get -u github.com/marios-pz/jwtverify/pkg`

# How to use it

Example with chi router

```go
// main program
package main

import (
	"log"
	"net/http"
	"github.com/marios-pz/jwtverify"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
)

func main() {
	token := jwtverify.NewJWTTokenManager("SECRET_KEY")
	r := chi.NewRouter()
    // ... handle chi router

	r.Route("/", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(token.JWTHandler)
            // private endpoints
		})

        // public endpoints
        // login handler
	})

	err = http.ListenAndServe(":3000", r)
	if err != nil {
		log.Println("There was an error listening on port :3000", err)
	}
}

```

```go
// login handler
token, err := token.GenerateToken(token.MakeClaim(user_id, lifespan))
if err != nil {
    helpers.RespondWithError(w, http.StatusInternalServerError, "could not create jwt token")
    return
}

cookie := http.Cookie{
    Name:     "<token-name>",
    Value:    token,
    Expires:  time.Now().Add(20 * time.Minute), // 20 minutes lifespan
    HttpOnly: true,
    SameSite: http.SameSiteStrictMode,
    Path:     "/",
    Secure:   true,
}

http.SetCookie(w, &cookie)

helpers.RespondWithSuccess(w, http.StatusCreated, "user created. here's a cookie!")
```
