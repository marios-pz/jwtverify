/*
Package jwtverify provides utilities for working with JSON Web Tokens (JWT) in Go.
A helper package for JWT operations.
*/
package jwtverify

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

// JWTSigningMethod specifies the signing method used for JWT tokens.
var JWTSigningMethod = jwt.SigningMethodHS256

// TokenManager represents a JWT token manager.
type JWTTokenManager struct {
	secretKey []byte // SecretKey is the secret key used for JWT token signing and validation.
}

// NewTokenManager creates a new TokenManager with the provided secret key.
func NewJWTTokenManager(secretKey string) *JWTTokenManager {
	return &JWTTokenManager{secretKey: []byte(secretKey)}
}

// GenerateToken generates a new JWT token with the given claims.
func (tm *JWTTokenManager) GenerateToken(claims jwt.Claims) (string, error) {
	// GenerateToken generates a JWT token with the provided claims.
	token := jwt.NewWithClaims(JWTSigningMethod, claims)
	return token.SignedString(tm.secretKey)
}

// MakeClaim creates and returns JWT claims for the given user ID and expiration time.
func (*JWTTokenManager) MakeClaim(userID int32, minutes int64) jwt.MapClaims {
	// MakeClaim creates JWT claims for the specified user ID and expiration time.
	timeout := time.Duration(minutes)
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Minute * timeout).Unix(),
	}
	return claims
}

// VerifyToken verifies the given JWT token string and returns the claims if valid.
func (tm *JWTTokenManager) VerifyToken(tokenString string) (jwt.Claims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return tm.secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("token validation failed")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("unable to parse Token Claims")
	}

	expirationTime := time.Unix(int64(claims["exp"].(float64)), 0)
	if time.Now().After(expirationTime) {
		return nil, errors.New("token has been expired")
	}

	return claims, nil
}

// JWTHandler returns an http.Handler middleware that verifies JWT tokens for incoming requests.
func (tm *JWTTokenManager) JWTHandler(next http.Handler) http.Handler {
	return tm.VerifyJWT(next.ServeHTTP)
}

// VerifyJWT returns an http.HandlerFunc that verifies JWT tokens before passing the request to the endpointHandler.
func (tm *JWTTokenManager) VerifyJWT(endpointHandler func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("You're Unauthorized due to No token in the Authorization header"))
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("You're Unauthorized due to invalid token format"))
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		verifiedClaims, err := tm.VerifyToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("You're Unauthorized due to error parsing the JWT"))
			return
		}

		if verifiedClaims != nil {
			endpointHandler(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("nauthorized due to invalid token"))
			return
		}
	})
}
