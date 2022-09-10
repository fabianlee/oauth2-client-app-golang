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

const (
	PORT = "8080"
)

var AUTH_PROVIDER = "" // github|adfs|keycloak
var AUTH_SERVER = ""   // FQDN of Auth Server
var CLIENT_ID = ""
var CLIENT_SECRET = ""
var SCOPE = ""
var REALM = ""               // keycloak specific
var CLIENT_BASE_APP_URL = "" // Client App URL, defaults to http://localhost:8080
var REDIRECT_URI = ""        // location on Client App where Auth server is allowed to redirect back

// init() executes before the main program
func init() {
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

	// resource on Client App where code is traded for ID and Access Token
	REDIRECT_URI, _ = osLookupEnv("REDIRECT_URI", "")
	if len(REDIRECT_URI) < 1 && "keycloak" == AUTH_PROVIDER {
		REDIRECT_URI = "*"
	} else if len(REDIRECT_URI) < 1 && "adfs" == AUTH_PROVIDER {
		REDIRECT_URI = fmt.Sprintf("%s/adfs/oauth2/token", CLIENT_BASE_APP_URL)
	} else {
		REDIRECT_URI = "*"
	}

	fmt.Printf("AUTH_PROVIDER=%s\n", AUTH_PROVIDER)
	fmt.Printf("AUTH_SERVER=%s\n", AUTH_SERVER)
	fmt.Printf("CLIENT_ID=%s\n", CLIENT_ID)
	fmt.Printf("CLIENT_SECRET=%s\n", CLIENT_SECRET)
	fmt.Printf("REALM=%s\n", REALM)
	fmt.Printf("SCOPE=%s\n", SCOPE)
	fmt.Printf("REDIRECT_URI=%s\n", REDIRECT_URI)
	fmt.Printf("CLIENT_BASE_APP_URL=%s\n", CLIENT_BASE_APP_URL)

}

func main() {

	// https://forfuncsake.github.io/post/2017/08/trust-extra-ca-cert-in-go-app/
	// https://stackoverflow.com/questions/12122159/how-to-do-a-https-request-with-bad-certificate
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	fmt.Println("NON-PRODUCTION! InsecureSkipVerify set to true, so Auth Server cert does not need to be provided.")

	// Returns links to the login route
	http.HandleFunc("/", rootHandler)

	// builds redirection URL+params to Authorization server
	http.HandleFunc("/login/github/", githubLoginHandler)
	http.HandleFunc("/login/ADFS/", adfsLoginHandler)
	http.HandleFunc("/login/keycloak/", keycloakLoginHandler)

	// callback from Auth Server that provides code, that can then be exchanged for Access Token
	http.HandleFunc("/login/github/callback", githubCallbackHandler)
	http.HandleFunc("/login/oauth2/code/adfs", adfsCallbackHandler)
	http.HandleFunc("/oidc_callback", keycloakCallbackHandler)

	// where authenticated user is redirected to shows basic user info
	http.HandleFunc("/loggedin", func(w http.ResponseWriter, r *http.Request) {
		loggedinHandler(w, r, "")
	})

	// start HTTP listener
	fmt.Println("[ UP ON PORT", PORT, "]")
	log.Panic(
		http.ListenAndServe(":"+PORT, nil),
	)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("AUTH_PROVIDER=%s\n", AUTH_PROVIDER)

	// show links where provider is configured in .env
	if "github" == AUTH_PROVIDER {
		fmt.Fprintf(w, `<a href="/login/github/">LOGIN to Github</a><br/>`)
	} else if "adfs" == AUTH_PROVIDER {
		fmt.Fprintf(w, `<a href="/login/ADFS/">LOGIN to ADFS</a><br/>`)
	} else if "keycloak" == AUTH_PROVIDER {
		fmt.Fprintf(w, `<a href="/login/keycloak/">LOGIN to Keycloak</a><br/>`)
	} else {
		fmt.Fprintf(w, `Did not find AUTH_PROVIDER `, AUTH_PROVIDER)
	}

}

// shows info about authenticated user
func loggedinHandler(w http.ResponseWriter, r *http.Request, userData string) {
	w.Header().Set("Cache-Control", "no-cache, private, max-age=0")
	if userData == "" {
		// Unauthorized users get an unauthorized message
		fmt.Fprintf(w, "UNAUTHORIZED!")
		return
	}

	w.Header().Set("Content-type", "application/json")

	// Prettifying the json
	var prettyJSON bytes.Buffer
	// json.indent is a library utility function to prettify JSON indentation
	parserr := json.Indent(&prettyJSON, []byte(userData), "", "\t")
	if parserr != nil {
		log.Panic("JSON parse error")
	}

	// Return the prettified JSON as a string
	fmt.Fprintf(w, string(prettyJSON.Bytes()))
}

// ****************************************************************************
// KEYCLOAK BEGIN
// ****************************************************************************

// https://www.baeldung.com/postman-keycloak-endpoints#2-authorize-endpoint
func keycloakLoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, private, max-age=0")

	redirect_uri := fmt.Sprintf("%s/oidc_callback", CLIENT_BASE_APP_URL)
	// unique values for state
	stateStr := makeNonce()

	// construct authorize URL to ADFS
	redirectURL := fmt.Sprintf("https://%s/realms/%s/protocol/openid-connect/auth?client_id=%s&redirect_uri=%s&scope=%s&access_type=offline&response_type=code&state=%s&openid.realm=%s", AUTH_SERVER, REALM, CLIENT_ID, redirect_uri, SCOPE, stateStr, REALM)
	fmt.Println(redirectURL)

	http.Redirect(w, r, redirectURL, 301)
}

func keycloakCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	fmt.Println("code returned from Keycloak:", code)

	_, keycloakAccessJSON := getKeycloakAccessTokenAndJSON(code)
	fmt.Println("keycloakAccessJSON:", keycloakAccessJSON)

	loggedinHandler(w, r, keycloakAccessJSON)
}

// https://www.baeldung.com/postman-keycloak-endpoints#3-token-endpoint
// https://www.appsdeveloperblog.com/keycloak-authorization-code-grant-example/
func getKeycloakAccessTokenAndJSON(code string) (string, string) {

	redirectURL := fmt.Sprintf("%s/oidc_callback", CLIENT_BASE_APP_URL)
	tokenURL := fmt.Sprintf("https://%s/realms/%s/protocol/openid-connect/token", AUTH_SERVER, REALM)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", CLIENT_ID)
	data.Set("client_secret", CLIENT_SECRET)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURL)

	fmt.Println("Exchanging code for token at", tokenURL)
	fmt.Println(data)

	req, reqerr := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
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

// ****************************************************************************
// KEYCLOAK END
// ****************************************************************************

// ****************************************************************************
// ADFS BEGIN
// ****************************************************************************

// https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios#request-an-authorization-code
// construct URL to authorize into ADFS using proper OAuth2 Application
func adfsLoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, private, max-age=0")

	redirectStr := fmt.Sprintf("%s/login/oauth2/code/adfs", CLIENT_BASE_APP_URL)
	// unique values for state and nonce
	stateStr := makeNonce()
	nonceStr := makeNonce()

	// construct authorize URL to ADFS
	redirectURL := fmt.Sprintf("https://%s/adfs/oauth2/authorize?resource=%s&response_type=code&client_id=%s&scope=%s&state=%s&redirect_uri=%s&nonce=%s", AUTH_SERVER, CLIENT_ID, CLIENT_ID, SCOPE, stateStr, redirectStr, nonceStr)
	fmt.Println(redirectURL)

	http.Redirect(w, r, redirectURL, 301)
}

// https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios#successful-response-2
// 'code' sent by the ADFS Authorization Server, up to us to decode embedded Access Token
func adfsCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	fmt.Println("code returned from ADFS:", code)

	_, adfsAccessJSON := getADFSAccessTokenAndJSON(code)
	fmt.Println("adfsAccessJSON:", adfsAccessJSON)

	loggedinHandler(w, r, adfsAccessJSON)
}

// https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios#request-an-access-token
// trade code for Access Token
func getADFSAccessTokenAndJSON(code string) (string, string) {

	redirectURL := fmt.Sprintf("%s/login/oauth2/code/adfs", CLIENT_BASE_APP_URL)
	fmt.Println("redirectURL: ", redirectURL)
	tokenURL := fmt.Sprintf("https://%s/adfs/oauth2/token", AUTH_SERVER)
	fmt.Println("adfs tokenURL:", tokenURL)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", CLIENT_ID)
	data.Set("client_secret", CLIENT_SECRET)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURL)

	req, reqerr := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if reqerr != nil {
		log.Panic("Request creation failed", reqerr)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded") // not absolutely required

	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		log.Panic("Request failed", resperr)
	}

	respbody, _ := ioutil.ReadAll(resp.Body)
	// Represents the response received
	type AccessTokenResponse struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		Resource     string `json:"resource"`
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

// ****************************************************************************
// ADFS END
// ****************************************************************************

// ****************************************************************************
// GITHUB BEGIN
// ****************************************************************************

func githubLoginHandler(w http.ResponseWriter, r *http.Request) {

	clientCallbackURL := fmt.Sprintf("%s/login/github/callback", CLIENT_BASE_APP_URL)
	redirectURL := fmt.Sprintf("https://%s/login/oauth/authorize?client_id=%s&redirect_uri=%s", AUTH_SERVER, CLIENT_ID, clientCallbackURL)
	fmt.Println(redirectURL)

	http.Redirect(w, r, redirectURL, 301)
}

func githubCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	githubAccessToken := getGithubAccessToken(code)

	// fetch user info remotely using access token
	githubData := getGithubData(githubAccessToken)

	loggedinHandler(w, r, githubData)
}

func getGithubData(accessToken string) string {
	req, reqerr := http.NewRequest("GET", "https://api.github.com/user", nil)
	if reqerr != nil {
		log.Panic("API Request creation failed")
	}

	authorizationHeaderValue := fmt.Sprintf("token %s", accessToken)
	req.Header.Set("Authorization", authorizationHeaderValue)

	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		log.Panic("Request failed")
	}

	respbody, _ := ioutil.ReadAll(resp.Body)

	return string(respbody)
}

func getGithubAccessToken(code string) string {

	requestBodyMap := map[string]string{"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code": code}
	requestJSON, _ := json.Marshal(requestBodyMap)

	req, reqerr := http.NewRequest("POST", "https://github.com/login/oauth/access_token", bytes.NewBuffer(requestJSON))
	if reqerr != nil {
		log.Panic("Request creation failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		log.Panic("Request failed")
	}

	respbody, _ := ioutil.ReadAll(resp.Body)

	// Represents the response received from Github
	type githubAccessTokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}

	var ghresp githubAccessTokenResponse
	json.Unmarshal(respbody, &ghresp)

	fmt.Println(ghresp.AccessToken)
	return ghresp.AccessToken
}

// ****************************************************************************
// GITHUB END
// ****************************************************************************

// get OS environment variable, have default value if non-existent
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

// simple 16 character nonce when unique id is required
func makeNonce() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		panic(err.Error())
	}
	return hex.EncodeToString(bytes)
}
