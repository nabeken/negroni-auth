package auth

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/AdRoll/goamz/dynamodb"
	"github.com/codegangsta/negroni"
	"golang.org/x/crypto/bcrypt"
)

// requireAuth writes error to client which initiates the authentication process
// or requires reauthentication.
func requireAuth(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Basic realm=\"Authorization Required\"")
	http.Error(w, "Not Authorized", http.StatusUnauthorized)
}

// Basic returns a negroni.HandlerFunc that authenticates via Basic Auth.
// Writes a http.StatusUnauthorized if authentication fails.
func Basic(username string, password string) negroni.HandlerFunc {
	var siteAuth = base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return func(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
		auth := req.Header.Get("Authorization")
		if !SecureCompare(auth, "Basic "+siteAuth) {
			requireAuth(w)
			return
		}
		r := w.(negroni.ResponseWriter)
		if r.Status() != http.StatusUnauthorized {
			next(w, req)
		}
	}
}

// getCred get userid, password from request.
func getCred(req *http.Request) (userId string, password string) {
	// Split authorization header.
	s := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 || s[0] != "Basic" {
		return "", ""
	}

	// Decode credential.
	cred, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return "", ""
	}

	// Split credential into userid, password.
	pair := strings.SplitN(string(cred), ":", 2)
	if len(pair) != 2 {
		return "", ""
	}

	// Assign return value.
	userId = pair[0]
	password = pair[1]

	return
}

// BasicDynamoDB returns a negroni.HandlerFunc that authenticates via Basic Auth. The user database is
// retrieved from DynamoDB table. Writes a http.StatusUnauthorized if authentication fails.
func BasicDynamoDB(tableName, userIdAttributeName, passwordAttributeName string) negroni.HandlerFunc {
	// Get DynamoDB table that store userid, password.
	basicAuthTable := getDynamoDBTable(tableName, userIdAttributeName)
	const cost = 12

	return func(w http.ResponseWriter, req *http.Request, next http.HandlerFunc) {
		// Extract userid, password from request.
		userId, password := getCred(req)

		if userId == "" {
			requireAuth(w)
			return
		}

		// Retrieve user credentials (userid, hashed password) from database by userid.
		key := &dynamodb.Key{HashKey: userId}
		userCred, err := basicAuthTable.GetItem(key)
		// If there is no user has this userid. Fail.
		if err != nil {
			requireAuth(w)
			return
		}
		// Extract hashed passwor from credentials.
		hashedPassword := userCred[passwordAttributeName].Value

		// Check if the password is correct.
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		// Password not correct. Fail.
		if err != nil {
			requireAuth(w)
			return
		}

		r := w.(negroni.ResponseWriter)

		// Password correct.
		if r.Status() != http.StatusUnauthorized {
			next(w, req)
		}
	}
}
