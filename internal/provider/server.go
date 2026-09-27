package provider

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"oidc-demo/internal/token"

	"github.com/golang-jwt/jwt/v5"
)

// Server is a fake login server that lives on your computer.
// It pretends to be both an OAuth2 server (gives permissions) and an OIDC server (proves identity).
// It remembers one-time codes and uses a secret key to stamp tokens.
type Server struct {
	Issuer string         // its own address, like "http://localhost:8085" — written into tokens as "iss"
	KP     *token.KeyPair // the secret key used to stamp all tokens

	mu    sync.Mutex           // a lock so two requests don't mess up the map at the same time
	codes map[string]codeEntry // remembers code -> what was asked, like a coat-check ticket
}

// codeEntry is the little note we keep when someone calls /authorize.
// Later at /token we check this note to make sure everything matches.
type codeEntry struct {
	ClientID        string    // which app asked (e.g. "demo-client")
	RedirectURI     string    // where to send the code back
	Scope           string    // what permissions were asked (e -  "read write" or "openid profile email")
	Nonce           string    // OIDC random value to stop replay
	Challenge       string    // PKCE scrambled secret
	ChallengeMethod string    // how it was scrambled: "S256" or "plain"
	Subject         string    // fake user id, always "user-123" here
	ExpiresAt       time.Time // when code stops being valid (5 minutes)
}

// discoveryDoc is the info card at /.well-known/openid-configuration.
// Apps download this first to learn where to login and where to get keys.
type discoveryDoc struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"` // where to login
	TokenEndpoint                    string   `json:"token_endpoint"`         // where to swap code for tokens
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`      // where to get user details
	JwksURI                          string   `json:"jwks_uri"`               // where to get public keys
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
}

// New makes a fresh fake server with a new secret key.
// You call this once when you run "oidc-demo serve".
func New(issuer string) (*Server, error) {
	// Make a new RSA key pair (private + public) for stamping tokens
	kp, err := token.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &Server{
		Issuer: strings.TrimSuffix(issuer, "/"), // remove "/" at end if present
		KP:     kp,
		codes:  make(map[string]codeEntry), // empty coat-check to start
	}, nil
}

// Handler builds the web router — it says which URL goes to which function.
// For example, "/authorize" goes to handleAuthorize. Called by serve to start the web server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()                                              // mux is like a front desk that sends visitors to the right room
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery) // discovery
	mux.HandleFunc("/jwks", s.handleJWKS)                                  // public keys
	mux.HandleFunc("/authorize", s.handleAuthorize)                        // login start
	mux.HandleFunc("/token", s.handleToken)                                // swap code for token
	mux.HandleFunc("/userinfo", s.handleUserinfo)                          // get user profile
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok")) // simple check to see if server is alive
	})
	return mux
}

// handleDiscovery sends the info card as JSON.
// Libraries like go-oidc call this to learn the server's addresses.
func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	doc := discoveryDoc{
		Issuer:                           s.Issuer,
		AuthorizationEndpoint:            s.Issuer + "/authorize",
		TokenEndpoint:                    s.Issuer + "/token",
		UserinfoEndpoint:                 s.Issuer + "/userinfo",
		JwksURI:                          s.Issuer + "/jwks",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile", "email", "offline_access", "read", "write"},
		ClaimsSupported:                  []string{"sub", "email", "name", "email_verified"},
		CodeChallengeMethodsSupported:    []string{"S256", "plain"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc) // turn struct into JSON and send
}

// handleJWKS sends the public key so others can check token stamps.
// Clients call GET /jwks to get this.
func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	jwks := s.KP.JWKS() // get public keys from the key pair
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// handleAuthorize is called when the app sends the user to login.
// It checks the request, makes a one-time code, remembers it, and sends the user back to the app.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Read what the app sent: ?client_id=...&redirect_uri=...&scope=...&code_challenge=...
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	scope := q.Get("scope")
	state := q.Get("state")
	nonce := q.Get("nonce")
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	responseType := q.Get("response_type")

	// Basic checks
	if clientID == "" || redirectURI == "" {
		http.Error(w, "missing client_id or redirect_uri", http.StatusBadRequest)
		return
	}
	if responseType != "code" {
		http.Error(w, "only response_type=code supported", http.StatusBadRequest)
		return
	}
	// Make a random one-time code from current time
	raw := fmt.Sprintf("%d", time.Now().UnixNano())
	h := sha256.Sum256([]byte(raw))
	code := base64.RawURLEncoding.EncodeToString(h[:16])

	// Save the code and what was asked, with 5-minute expiry
	s.mu.Lock() // lock so no one else changes the map at same time
	s.codes[code] = codeEntry{
		ClientID:        clientID,
		RedirectURI:     redirectURI,
		Scope:           scope,
		Nonce:           nonce,
		Challenge:       challenge,
		ChallengeMethod: method,
		Subject:         "user-123", // our fake logged-in person
		ExpiresAt:       time.Now().Add(5 * time.Minute),
	}
	s.mu.Unlock() // unlock

	// Build the redirect back to the app: redirect_uri?code=ABC&state=XYZ
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	qs := u.Query()
	qs.Set("code", code)
	if state != "" {
		qs.Set("state", state) // send state back so app can check it's the same request
	}
	u.RawQuery = qs.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound) // 302 = "go here"
}

// handleToken looks at what the app wants: swapping a code for tokens, or app-only login.
// It reads grant_type and calls the right helper.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil { // read the POST form body
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	grant := r.Form.Get("grant_type")
	switch grant {
	case "authorization_code":
		s.handleAuthCode(w, r) // normal login with code
	case "client_credentials":
		s.handleClientCreds(w, r) // app-only, no person
	default:
		http.Error(w, "unsupported grant_type", http.StatusBadRequest)
	}
}

// handleAuthCode swaps a one-time code for tokens.
// It checks the code is real, not expired, PKCE matches, then makes JWTs and returns them.
func (s *Server) handleAuthCode(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	verifier := r.Form.Get("code_verifier") // PKCE secret the app kept
	redirectURI := r.Form.Get("redirect_uri")
	clientID := r.Form.Get("client_id")

	// Find and delete the code (one-time use, like a coat-check ticket you tear after use)
	s.mu.Lock()
	entry, ok := s.codes[code]
	if ok {
		delete(s.codes, code)
	}
	s.mu.Unlock()

	if !ok {
		http.Error(w, `{"error":"invalid_grant","error_description":"code not found"}`, http.StatusBadRequest)
		return
	}
	if time.Now().After(entry.ExpiresAt) {
		http.Error(w, `{"error":"invalid_grant","error_description":"code expired"}`, http.StatusBadRequest)
		return
	}
	// Make sure redirect_uri is same as at /authorize (stops theft)
	if entry.RedirectURI != redirectURI {
		if redirectURI != "" && entry.RedirectURI != redirectURI {
			http.Error(w, `{"error":"invalid_grant","error_description":"redirect_uri mismatch"}`, http.StatusBadRequest)
			return
		}
	}
	if entry.ClientID != clientID && clientID != "" {
		http.Error(w, `{"error":"invalid_grant","error_description":"client_id mismatch"}`, http.StatusBadRequest)
		return
	}
	// If PKCE was used (challenge exists), check verifier matches challenge
	if entry.Challenge != "" {
		if verifier == "" {
			http.Error(w, `{"error":"invalid_grant","error_description":"code_verifier required"}`, http.StatusBadRequest)
			return
		}
		var computed string
		if strings.EqualFold(entry.ChallengeMethod, "plain") {
			computed = verifier // plain means no scrambling
		} else {
			h := sha256.Sum256([]byte(verifier))
			computed = base64.RawURLEncoding.EncodeToString(h[:]) // S256 = scramble verifier and compare
		}
		if computed != entry.Challenge {
			http.Error(w, `{"error":"invalid_grant","error_description":"pkce verification failed"}`, http.StatusBadRequest)
			return
		}
	}

	cid := entry.ClientID
	if cid == "" {
		cid = clientID
	}
	scope := entry.Scope
	if scope == "" {
		scope = "openid profile email"
	}

	// Make an access_token (always) — this lets the app call APIs
	accessToken, err := token.NewAccessToken(s.KP, s.Issuer, cid, entry.Subject, scope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        scope,
	}

	// If scope has "openid", also make an id_token — this proves WHO the user is (OIDC)
	if strings.Contains(scope, "openid") {
		idTok, err := token.NewIDToken(s.KP, s.Issuer, cid, entry.Subject, entry.Nonce)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp["id_token"] = idTok
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleClientCreds is for app-to-app login, no person involved.
// It just makes an access_token for the app itself.
func (s *Server) handleClientCreds(w http.ResponseWriter, r *http.Request) {
	clientID := r.Form.Get("client_id")
	scope := r.Form.Get("scope")
	if scope == "" {
		scope = "read"
	}
	if clientID == "" {
		clientID = "demo-client"
	}
	// For this flow, subject is the app itself, since no person
	tok, err := token.NewAccessToken(s.KP, s.Issuer, clientID, clientID, scope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp := map[string]interface{}{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        scope,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleUserinfo returns the fake person's profile if the access_token is valid.
// App calls this with "Authorization: Bearer <token>" after login.
func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	tok := strings.TrimPrefix(auth, "Bearer ") // remove "Bearer " to get just the token
	if tok == "" {
		http.Error(w, `{"error":"missing token"}`, http.StatusUnauthorized)
		return
	}
	// Check the token is real: correct stamp and correct issuer
	claims := &token.AccessClaims{}
	parsed, err := jwt.ParseWithClaims(tok, claims, func(t *jwt.Token) (interface{}, error) {
		return &s.KP.PrivateKey.PublicKey, nil // use public key to check stamp
	}, jwt.WithIssuer(s.Issuer))
	if err != nil || !parsed.Valid {
		http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
		return
	}
	// Return fake profile for the user in the token
	resp := map[string]interface{}{
		"sub":            claims.Subject, // user id
		"email":          "demo@example.com",
		"name":           "Demo User",
		"email_verified": true,
		"iss":            s.Issuer,
		"client_id":      claims.ClientID,
		"scope":          claims.Scope,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
