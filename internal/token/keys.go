package token

import (
	"crypto/rand" // to make random numbers safely
	"crypto/rsa"  // to make RSA keys (math that powers JWT signing)
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4" // helps put keys into JSON format (JWKS)
	"github.com/golang-jwt/jwt/v5"  // helps make and read JWT tokens
)

// KeyID is a name tag for our key, like a label on a key.
// We put this in the token header so the checker knows which key to use.
const KeyID = "demo-kid-1"

// KeyPair is a box that holds one secret key and its public version.
// Imagine a stamp: private key is the stamp you keep hidden, public key is the ink pattern everyone can check.
type KeyPair struct {
	PrivateKey *rsa.PrivateKey // secret part, used to sign (stamp) tokens — keep hidden
	PublicJWK  jose.JSONWebKey // public part, sent to others so they can verify tokens
	PrivateJWK jose.JSONWebKey // same private key but in JSON shape
}

// GenerateKeyPair makes a brand new RSA key.
// Think of it as making a new lock and key. Called once when our fake server starts.
func GenerateKeyPair() (*KeyPair, error) {
	// Make a 2048-bit RSA private key using secure random numbers
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	// Wrap the public part as a JWK (JSON Web Key) so it can be sent as JSON at /jwks
	jwk := jose.JSONWebKey{
		Key:       &priv.PublicKey,
		KeyID:     KeyID,
		Algorithm: string(jose.RS256), // RS256 = RSA with SHA256, the signing method
		Use:       "sig",              // "sig" means signing
	}
	// Also wrap the private part as JWK (we don't share this)
	privJWK := jose.JSONWebKey{
		Key:       priv,
		KeyID:     KeyID,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	return &KeyPair{PrivateKey: priv, PublicJWK: jwk, PrivateJWK: privJWK}, nil
}

// JWKS returns the public keys as a JSON Web Key Set.
// This is what the server sends when someone calls GET /jwks.
func (k *KeyPair) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{k.PublicJWK}}
}

// SignClaims takes some info (claims) and stamps it with our private key to make a JWT string.
// Anyone with the public key can later check the stamp is real.
func (k *KeyPair) SignClaims(claims jwt.Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims) // make a new token with RS256
	t.Header["kid"] = KeyID                                // add key id to header
	return t.SignedString(k.PrivateKey)                    // sign and return like "header.payload.signature"
}

// GenerateVerifier makes a random secret for PKCE.
// PKCE is a trick to prove you are the same app that started the login.
// You make a secret (verifier), send only its scrambled version (challenge), later reveal the secret.
func GenerateVerifier() (string, error) {
	b := make([]byte, 32) // 32 random bytes
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Turn bytes into a safe text string without padding
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ChallengeS256 scrambles the verifier with SHA256.
// You send this to /authorize. Later at /token you send the original verifier to prove it's you.
func ChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier)) // hash it
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// VerifyChallenge checks if verifier matches the challenge you sent earlier.
// Server uses this at /token to stop hackers who stole the code.
func VerifyChallenge(verifier, challenge string) bool {
	return ChallengeS256(verifier) == challenge
}

// AccessClaims is the inside of an access_token.
// It says: who it's for, what app asked for it, and what permissions (scope) it has.
type AccessClaims struct {
	jwt.RegisteredClaims        // common fields: who made it (iss), who it's about (sub), who can use it (aud), expiry (exp)
	Scope                string `json:"scope,omitempty"`     // permissions like "read write"
	ClientID             string `json:"client_id,omitempty"` // which app requested it
}

// IDClaims is the inside of an id_token.
// This is the extra token that OIDC adds to prove WHO the person is. OAuth2 alone does NOT have this.
type IDClaims struct {
	jwt.RegisteredClaims
	Email         string `json:"email,omitempty"`          // person's email
	Name          string `json:"name,omitempty"`           // person's name
	EmailVerified bool   `json:"email_verified,omitempty"` // is email confirmed?
	Nonce         string `json:"nonce,omitempty"`          // random value to stop replay attacks
}

// NewAccessToken makes a new access_token, stamps it, and returns the JWT string.
// Called after code exchange or for client_credentials.
func NewAccessToken(kp *KeyPair, issuer, clientID, subject, scope string) (string, error) {
	now := jwt.NewNumericDate(time.Now())                // now
	exp := jwt.NewNumericDate(time.Now().Add(time.Hour)) // expires in 1 hour
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,                     // who created the token (our server)
			Subject:   subject,                    // who the token is about (user id like "user-123")
			Audience:  jwt.ClaimStrings{clientID}, // which app can use it
			ExpiresAt: exp,
			IssuedAt:  now,
			ID:        fmt.Sprintf("at-%d", now.UnixNano()), // unique id for token
		},
		Scope:    scope,
		ClientID: clientID,
	}
	return kp.SignClaims(claims) // stamp and return
}

// NewIDToken makes a new id_token that proves the person's identity.
// Only made when scope includes "openid" — that's how you know it's OIDC, not just OAuth2.
func NewIDToken(kp *KeyPair, issuer, clientID, subject, nonce string) (string, error) {
	now := jwt.NewNumericDate(time.Now())
	exp := jwt.NewNumericDate(time.Now().Add(time.Hour))
	claims := IDClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,                    // user id
			Audience:  jwt.ClaimStrings{clientID}, // must match the app that asked
			ExpiresAt: exp,
			IssuedAt:  now,
			ID:        fmt.Sprintf("it-%d", now.UnixNano()),
		},
		Email:         "demo@example.com", // fake user data for demo
		Name:          "Demo User",
		EmailVerified: true,
		Nonce:         nonce, // echo back the nonce from login start
	}
	return kp.SignClaims(claims)
}
