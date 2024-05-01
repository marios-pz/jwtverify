package jwtverify_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt"
	jv "github.com/marios-pz/jwtverify/pkg"
)

func TestGenerateToken(t *testing.T) {
	tm := jv.NewJWTTokenManager("secret")
	claims := tm.MakeClaim(123, 60)
	_, err := tm.GenerateToken(claims)
	if err != nil {
		t.Errorf("GenerateToken failed: %v", err)
	}
}

func TestVerifyToken(t *testing.T) {
	tm := jv.NewJWTTokenManager("secret")
	claims := tm.MakeClaim(123, 60)
	token, err := tm.GenerateToken(claims)
	if err != nil {
		t.Errorf("GenerateToken failed: %v", err)
	}

	verifiedClaims, err := tm.VerifyToken(token)
	if err != nil {
		t.Errorf("VerifyToken failed: %v", err)
	}

	if verifiedClaims == nil {
		t.Error("Verified claims are nil")
	}

	// Type assert verifiedClaims to jwt.MapClaims
	vClaims, ok := verifiedClaims.(jwt.MapClaims)
	if !ok {
		t.Error("Failed to type assert verifiedClaims to jwt.MapClaims")
	}

	if verifiedUserID, ok := vClaims["user_id"].(float64); !ok || int32(verifiedUserID) != claims["user_id"].(int32) {
		t.Error("Verified claims do not match the claims used for token generation")
	}
}

func TestJWTHandler(t *testing.T) {
	// Create a dummy HTTP handler for testing purposes
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tm := jv.NewJWTTokenManager("secret")
	handler := tm.JWTHandler(dummyHandler)

	// Create a mock HTTP request with no Authorization header
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}
