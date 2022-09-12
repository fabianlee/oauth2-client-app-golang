// Implementation of 'Client Application' in an OAuth2 Authorization Code flow
//
// Using ADFS 2019: https://fabianlee.org/2022/08/22/microsoft-configuring-an-application-group-for-oauth2-oidc-on-adfs-2019/
// Using Keycloak: https://fabianlee.org/2022/09/10/kubernetes-keycloak-iam-deployed-into-kubernetes-cluster-for-oauth2-oidc/
//
// Originally based on sharmarajdaksh's Github OAuth2 integration
// https://github.com/sharmarajdaksh/github-oauth-go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	// for URL encoding
	"net/url"
	"strings"

	// for nonce
	"crypto/rand"
	"encoding/hex"

	// to set InsecureSkipVerify for TLS
	"crypto/tls"

	// pull values from .env file
	"github.com/joho/godotenv"

	// decode JWT, https://github.com/square/go-jose
	// go get gopkg.in/square/go-jose.v2
	"gopkg.in/square/go-jose.v2/jwt"
)

// web listening port
const (
	PORT = "8080"
)

// environment variables used to
var AUTH_PROVIDER = ""       // github|adfs|keycloak|okta|spotify
var AUTH_SERVER = ""         // FQDN of Auth Server
var CLIENT_ID = ""           // OAUTH2 client id
var CLIENT_SECRET = ""       // OAUTH2 client secret
var SCOPE = ""               // OAUTH2 scope
var REALM = ""               // Keycloak specific
var CLIENT_BASE_APP_URL = "" // Client App URL, defaults to http://localhost:8080
var REDIRECT_URI = ""        // location on Client App where Auth server is allowed to redirect back
var CALLBACK_URI = ""        // location on Client App where Auth server will send code
var IS_OIDC = true           // will be set to false if only OAuth2 (and not OIDC)

// metadata about Auth Server endpoints
// typically pulled from well-known remote location
type MetadataResponse struct {
	issuer                 string
	authorization_endpoint string
	token_endpoint         string
	jwks_uri               string
	userinfo_endpoint      string
	end_session_endpoint   string
}

// stores Auth Server endpoints
var metadata MetadataResponse

// init() executes before the main program
// using this to pull values from environment variables, setup defaults,
// and pull Auth Server metadata
func init() {
	// https://forfuncsake.github.io/post/2017/08/trust-extra-ca-cert-in-go-app/
	// https://stackoverflow.com/questions/12122159/how-to-do-a-https-request-with-bad-certificate
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	fmt.Println("NON-PRODUCTION! InsecureSkipVerify set to true, so Auth Server cert does not need to be provided.")

	// loads values from .env into the system
	if err := godotenv.Load(); err != nil {
		fmt.Println("No .env file found, using only explicit environment variables")
	} else {
		fmt.Println(".env file found")
	}

	var exists = true
	AUTH_PROVIDER, exists = osLookupEnv("AUTH_PROVIDER", "")
	if !exists {
		log.Panic("ERROR need to define AUTH_PROVIDER")
	}
	AUTH_SERVER, exists = osLookupEnv("AUTH_SERVER", "")
	if "github" == AUTH_SERVER { // no need to specify since it is a static location
		AUTH_SERVER = "github.com"
	} else if !exists {
		log.Panic("ERROR need to define AUTH_SERVER")
	}
	CLIENT_ID, exists = osLookupEnv("CLIENT_ID", "")
	if !exists {
		log.Panic("ERROR need to define CLIENT_ID")
	}
	CLIENT_SECRET, exists = osLookupEnv("CLIENT_SECRET", "")
	if !exists {
		log.Panic("ERROR need to define CLIENT_SECRET")
	}

	REALM, _ = osLookupEnv("REALM", "")
	if "keycloak" == AUTH_SERVER && len(REALM) < 1 {
		log.Panic("ERROR Keycloak servers must have REALM set")
	}

	SCOPE, exists = osLookupEnv("SCOPE", "")
	if !exists {
		log.Panic("ERROR need to define SCOPE, at minimum 'openid'")
	}

	// local Client App for redirection
	CLIENT_BASE_APP_URL, _ = osLookupEnv("CLIENT_BASE_APP_URL", "http://localhost:8080")

	// base location on Client App where Auth Server is allowed to callback
	REDIRECT_URI, _ = osLookupEnv("REDIRECT_URI", "")
	if len(REDIRECT_URI) < 1 && "adfs" == AUTH_PROVIDER {
                // an "*" would not work for ADFS
		REDIRECT_URI = fmt.Sprintf("%s/adfs/oauth2/token", CLIENT_BASE_APP_URL)
	} else {
		REDIRECT_URI = "*"
	}

	// URI on Client App where code is traded for ID and Access Token
        //
        // these values all depend on how you configure your Auth Server Client app
        // I have picked some of these depending on Auth Server defaults, 
        // and others based on defaults coming from Java Spring Security and Python Flask-OIDC client libraries
        //
        // override by setting environment variable 'CALLBACK_URI'
	DEFAULT_CALLBACK_URI := ""
	switch AUTH_PROVIDER {
	case "adfs":
		DEFAULT_CALLBACK_URI = "/login/oauth2/code/adfs"
	case "keycloak":
		DEFAULT_CALLBACK_URI = "/oidc_callback"
	case "okta":
		DEFAULT_CALLBACK_URI = "/authorization-code/callback"
	case "github":
		DEFAULT_CALLBACK_URI = "/login/github/callback"
		IS_OIDC = false
	case "spotify":
		DEFAULT_CALLBACK_URI = "/login/oauth2/code/spotify"
		IS_OIDC = false
	default:
		DEFAULT_CALLBACK_URI = "/callback"
	}
	CALLBACK_URI, _ = osLookupEnv("CALLBACK_URI", DEFAULT_CALLBACK_URI)

	fmt.Printf("AUTH_PROVIDER=%s\n", AUTH_PROVIDER)
	fmt.Printf("AUTH_SERVER=%s\n", AUTH_SERVER)
	fmt.Printf("CLIENT_ID=%s\n", CLIENT_ID)
	fmt.Printf("CLIENT_SECRET=%s\n", CLIENT_SECRET)
	fmt.Printf("REALM=%s\n", REALM)
	fmt.Printf("SCOPE=%s\n", SCOPE)
	fmt.Printf("REDIRECT_URI=%s\n", REDIRECT_URI)
	fmt.Printf("CLIENT_BASE_APP_URL=%s\n", CLIENT_BASE_APP_URL)
	fmt.Printf("CALLBACK_URI=%s\n", CALLBACK_URI)
	fmt.Printf("IS_OIDC=%t\n", IS_OIDC)

	// OIDC metadata URL
	loadAuthServerMetadata()
}

// OIDC compliant providers all have metadata available publicly about endpoints it offers
// we use this to lookup authorization, token, and logout endpoints
// and for OAuth2-only providers (e.g. github and spotify) we manually populate
func loadAuthServerMetadata() {

	metadataURL := ""
	switch AUTH_PROVIDER {
	case "adfs":
		metadataURL = fmt.Sprintf("https://%s/adfs/.well-known/openid-configuration", AUTH_SERVER)
	case "keycloak":
		metadataURL = fmt.Sprintf("https://%s/realms/%s/.well-known/openid-configuration", AUTH_SERVER, REALM)
	case "okta":
		metadataURL = fmt.Sprintf("https://%s/.well-known/openid-configuration", AUTH_SERVER)
	case "github":
		metadata.authorization_endpoint = "https://github.com/login/oauth/authorize"
		metadata.token_endpoint = "https://github.com/login/oauth/access_token"
		// https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps#3-use-the-access-token-to-access-the-api
		metadata.userinfo_endpoint = "https://api.github.com/user"
	case "spotify":
		metadata.authorization_endpoint = "https://accounts.spotify.com/authorize"
		metadata.token_endpoint = "https://accounts.spotify.com/api/token"
		// https://developer.spotify.com/documentation/web-api/reference/#/operations/get-current-users-profile
		metadata.userinfo_endpoint = "https://api.spotify.com/v1/me"
	}

	if metadataURL == "" {
		fmt.Println("No metadata for this Auth Server, so .well-known/openid-configuration not being pulled")
	} else {

		req, reqerr := http.NewRequest("GET", metadataURL, nil)
		if reqerr != nil {
			log.Panic("Request creation failed", reqerr)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, resperr := http.DefaultClient.Do(req)
		if resperr != nil {
			log.Panic("Request failed", resperr)
		}
		respbody, _ := ioutil.ReadAll(resp.Body)
		//fmt.Println("=======", fmt.Sprintf("%s", respbody), "========")
		json.Unmarshal([]byte(respbody), &metadata)

		// bring in JSON in uknown format
		var unknown map[string]interface{}
		err := json.Unmarshal([]byte(respbody), &unknown)
		if err != nil {
			log.Panic("unknown marshall failed", err)
		}

		// manually stuff into structure
		metadata.issuer = unknown["issuer"].(string)
		metadata.authorization_endpoint = unknown["authorization_endpoint"].(string)
		metadata.token_endpoint = unknown["token_endpoint"].(string)
		metadata.userinfo_endpoint = unknown["userinfo_endpoint"].(string)
		metadata.end_session_endpoint = unknown["end_session_endpoint"].(string)
	}

	// show struture values of Auth Server metadata
	fmt.Println("==== AUTH SERVER METADATA ====")
	fmt.Println("issuer: " + metadata.issuer)
	fmt.Println("authorization_endpoint: " + metadata.authorization_endpoint)
	fmt.Println("token_endpoint: " + metadata.token_endpoint)
	fmt.Println("userinfo_endpoint: " + metadata.userinfo_endpoint)
	fmt.Println("end_session_endpoint: " + metadata.end_session_endpoint)
}

func main() {

	// Returns links to the login route
	http.HandleFunc("/", rootHandler)

	// builds redirection URL+params to Authorization server
	http.HandleFunc("/login/", loginHandler)

	// callback from Auth Server that sends code
	// then opaquely exchanged for Access Token (end user cannot see this interaction)
	http.HandleFunc(CALLBACK_URI, callbackHandler)

	// start HTTP listener
	fmt.Println("[ LISTENING ON PORT", PORT, "]")
	log.Panic(
		http.ListenAndServe(":"+PORT, nil),
	)
}

// gives end user a login link
// and hint as to whether the provider is OIDC or just OAUTH2
func rootHandler(w http.ResponseWriter, r *http.Request) {

	if IS_OIDC {
		fmt.Fprintf(w, "<a href=\"/login/\">OIDC LOGIN to %s</a><br/>", AUTH_PROVIDER)
	} else {
		fmt.Fprintf(w, "<a href=\"/login/\">OAUTH2 LOGIN to %s </a><br/>", AUTH_PROVIDER)
	}

}

// shows info about logged in user
// logout link if Auth Server is OIDC provider
func loggedinHandler(w http.ResponseWriter, r *http.Request, userData string) {
	w.Header().Set("Cache-Control", "no-cache, private, max-age=0")
	if userData == "" {
		// Unauthorized users get an unauthorized message
		fmt.Fprintf(w, "UNAUTHORIZED!")
		return
	}

	// Prettifying the json
	var prettyJSON bytes.Buffer
	// json.indent is a library utility function to prettify JSON indentation
	parserr := json.Indent(&prettyJSON, []byte(userData), "", "\t")
	if parserr != nil {
		log.Panic("JSON parse error")
	}

	if IS_OIDC {
		logoutURL := fmt.Sprintf("%s?post_logout_redirect_uri=%s/&client_id=%s", metadata.end_session_endpoint, CLIENT_BASE_APP_URL, CLIENT_ID)
		fmt.Println("logoutURL: ", logoutURL)

		w.Header().Set("Content-type", "text/html")
		fmt.Fprintf(w, "<a href=\"%s\">OIDC LOGOUT from %s </a><br/>", logoutURL, AUTH_PROVIDER)
		fmt.Fprintf(w, `<textarea cols="140" rows="40" style=\"font-size: small;\">`)
		fmt.Fprintf(w, string(prettyJSON.Bytes()))
		fmt.Fprintf(w, `</textarea>`)

	} else {
		// non-OIDC does not have logout, so just show user info data
		w.Header().Set("Content-type", "application/json")
		fmt.Fprintf(w, string(prettyJSON.Bytes()))
	}
}

// constructs URL and redirects to Auth Server authorization endpoint
// sends: client_id, redirect_uri, scope
// Auth Server will then perform the login process, and send to callback with code
func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, private, max-age=0")

	callback_uri := fmt.Sprintf("%s%s", CLIENT_BASE_APP_URL, CALLBACK_URI)
	fmt.Println("Auth Server be redirecting code back to " + callback_uri)

	// unique value, coutermeasure for known attacks
	stateStr := makeUniqueValue()

	// minimal authentication params
	authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s&response_type=code&state=%s", metadata.authorization_endpoint, CLIENT_ID, callback_uri, SCOPE, stateStr)

	// certain providers need appending of fields
	switch AUTH_PROVIDER {
	case "adfs":
		nonceStr := makeUniqueValue()
		authURL = fmt.Sprintf("%s&resource=%s&nonce=%s", authURL, CLIENT_ID, nonceStr)
	case "keycloak":
		authURL = fmt.Sprintf("%s&access_type=offline&openid.realm=%s", authURL, REALM)
	case "okta":
		// intentionally no changes
	case "github":
		// intentionally no changes
		// github ignoes extra 'response_type' param being sent
	case "spotify":
		// intentionally no changes
	default:
		// intentionally no changes
	}
	fmt.Println(authURL)

	http.Redirect(w, r, authURL, 301)
}

// callback from Authentication Server that passes in 'code'
// This is the opaque exchange between this Client App and the Auth Server (will not be seen by user "Resource Owner")
// that retrieves an Access Token from Auth Server
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	fmt.Println("code returned from "+AUTH_PROVIDER+":", code)

	if IS_OIDC {
		_, oidcAccessJSON := getOIDCAccessTokenAndJSON(code)
		loggedinHandler(w, r, oidcAccessJSON)
	} else {
		accessToken := getOAuth2OnlyAccessToken(code)
		userinfoJSON := getOAuth2UserInfo(accessToken)
		loggedinHandler(w, r, userinfoJSON)
	}
}

// OIDC providers will return detailed ID and Access Token
func getOIDCAccessTokenAndJSON(code string) (string, string) {

	callbackURL := fmt.Sprintf("%s%s", CLIENT_BASE_APP_URL, CALLBACK_URI)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", CLIENT_ID)
	data.Set("client_secret", CLIENT_SECRET)
	data.Set("code", code)
	data.Set("redirect_uri", callbackURL)

	fmt.Println("Exchanging code for token at", metadata.token_endpoint)
	fmt.Println(data)

	req, reqerr := http.NewRequest("POST", metadata.token_endpoint, strings.NewReader(data.Encode()))
	if reqerr != nil {
		log.Panic("Request creation failed", reqerr)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded") // required to post correctly

	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		log.Panic("Request failed", resperr)
	}

	respbody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("=======", fmt.Sprintf("%s", respbody), "========")
	// Represents the response received
	type AccessTokenResponse struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		//Resource     string `json:"resource"`
	}
	var ghresp AccessTokenResponse
	json.Unmarshal(respbody, &ghresp)

	// FIRST decode the entire response, one of the fields is AccessToken
	// use unknown map interface to show all json fields for debugging
	var unknown map[string]interface{}
	err := json.Unmarshal([]byte(respbody), &unknown)
	if err != nil {
		log.Panic("unknown marshall failed", err)
	}
	fmt.Println("==BEGIN ALL DECODED FIELDS============")
	for k, v := range unknown {
		fmt.Println(k, ":", v)
	}
	fmt.Println("==END ALL DECODED FIELDS============")
	//fmt.Println(ghresp.AccessToken)
	//fmt.Println("scope:",ghresp.Scope)

	// https://stackoverflow.com/questions/45405626/how-to-decode-a-jwt-token-in-go
	// decode JWT token without verifying the signature
	var claims map[string]interface{} // generic map to store parsed token

	token, _ := jwt.ParseSigned(ghresp.IDToken)
	_ = token.UnsafeClaimsWithoutVerification(&claims)
	fmt.Println("==BEGIN DECODED ID TOKEN JWT============")
	for k, v := range claims {
		fmt.Println(k, ":", v)
	}
	fmt.Println("==END DECODED ID TOKEN JWT============")

	token, _ = jwt.ParseSigned(ghresp.AccessToken)
	_ = token.UnsafeClaimsWithoutVerification(&claims)
	fmt.Println("==BEGIN DECODED ACCESS TOKEN JWT============")
	for k, v := range claims {
		fmt.Println(k, ":", v)
	}
	fmt.Println("==END DECODED ACCESS TOKEN JWT============")

	accessTokenJSON, err := json.Marshal(claims)
	if err != nil {
		log.Panic("JSON marshal of access token failed", err)
	}
	return ghresp.AccessToken, string(accessTokenJSON)
}

// OAuth2-only providers (not OIDC compliant)  will return only Access Token and not ID Token
func getOAuth2OnlyAccessToken(code string) string {

	callbackURL := fmt.Sprintf("%s%s", CLIENT_BASE_APP_URL, CALLBACK_URI)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", CLIENT_ID)
	data.Set("client_secret", CLIENT_SECRET)
	data.Set("code", code)
	data.Set("redirect_uri", callbackURL)

	fmt.Println("Exchanging code for token at", metadata.token_endpoint)
	fmt.Println(data)

	req, reqerr := http.NewRequest("POST", metadata.token_endpoint, strings.NewReader(data.Encode()))
	if reqerr != nil {
		log.Panic("Request creation failed", reqerr)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded") // required to post correctly

	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		log.Panic("Request failed", resperr)
	}

	respbody, _ := ioutil.ReadAll(resp.Body)
	//fmt.Println("=======", fmt.Sprintf("%s", respbody), "========")
	// Represents the response received
	type AccessTokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	var ghresp AccessTokenResponse
	json.Unmarshal(respbody, &ghresp)

	// FIRST decode the entire response, one of the fields is AccessToken
	// use unknown map interface to show all json fields for debugging
	var unknown map[string]interface{}
	err := json.Unmarshal([]byte(respbody), &unknown)
	if err != nil {
		log.Panic("unknown marshall failed", err)
	}
	fmt.Println("==BEGIN ALL DECODED FIELDS============")
	for k, v := range unknown {
		fmt.Println(k, ":", v)
	}
	fmt.Println("==END ALL DECODED FIELDS============")

	return ghresp.AccessToken
}

// OAuth2-only providers (not OIDC compliant)  will not have detailed Access Token,
// rely instead on pulling from a provider's API user endpoint (which hopefully they have)
func getOAuth2UserInfo(accessToken string) string {
	req, reqerr := http.NewRequest("GET", metadata.userinfo_endpoint, nil)
	fmt.Println("Pulling user info from: ", metadata.userinfo_endpoint)
	if reqerr != nil {
		log.Panic("User Info URL creation failed")
	}
	authorizationHeaderValue := fmt.Sprintf("Bearer %s", accessToken)
	req.Header.Set("Authorization", authorizationHeaderValue)

	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		log.Panic("User Info Request failed")
	}

	respbody, _ := ioutil.ReadAll(resp.Body)

	return string(respbody)
}

// get OS environment variable, pass default value if non-existent
func osLookupEnv(key string, defaultValue string) (string, bool) {
	val, exists := os.LookupEnv(key)
	if exists {
		return val, true
	} else {
		if defaultValue == "" {
			return "", false
		} else {
			return defaultValue, true
		}
	}
}

// simple 16 character nonce
// used for unique values in exchanges to avoid several known attacks against protocol
func makeUniqueValue() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		panic(err.Error())
	}
	return hex.EncodeToString(bytes)
}
