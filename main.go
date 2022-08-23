// 'Client Application' in an OAuth2 Authorization Code flow
// with ADFS 2019 as Authentication Server
//
// Based off sharmarajdaksh's Google OAuth2 integration
// https://github.com/sharmarajdaksh/github-oauth-go
// https://sharmarajdaksh.github.io/blog/github-oauth-with-go
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

// init() executes before the main program
func init() {
	// loads values from .env into the system
	if err := godotenv.Load(); err != nil {
		fmt.Println("No .env file found, using only explicit environment variables")
	}else {
		fmt.Println(".env file found")
        }
}

func main() {

        // https://forfuncsake.github.io/post/2017/08/trust-extra-ca-cert-in-go-app/
        // https://stackoverflow.com/questions/12122159/how-to-do-a-https-request-with-bad-certificate
        http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	fmt.Println("InsecureSkipVerify set to true, doing this so ADFS cert does not need to be provided")

	// Returns links to the login route
	http.HandleFunc("/", rootHandler)

	// builds redirection URL+params to Authorization server
	http.HandleFunc("/login/github/", githubLoginHandler)
	http.HandleFunc("/login/ADFS/", adfsLoginHandler)

	// callback from Auth Server that provides code, that can then be exchanged for Access Token
	http.HandleFunc("/login/github/callback", githubCallbackHandler)
	http.HandleFunc("/login/oauth2/code/adfs", adfsCallbackHandler)

	// where authenticated user is redirected to shows basic user info
	http.HandleFunc("/loggedin", func(w http.ResponseWriter, r *http.Request) {
		loggedinHandler(w, r, "")
	})

	// start HTTP listener
	fmt.Println("[ UP ON PORT",PORT,"]")
	log.Panic(
		http.ListenAndServe(":"+PORT, nil),
	)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {

        // show links where provider is configured in .env
        if _, exists := osLookupEnv("GITHUB_CLIENT_ID",""); exists {
	  fmt.Fprintf(w, `<a href="/login/github/">LOGIN to Github</a><br/>`)
        }
        if _, exists := osLookupEnv("ADFS_CLIENT_ID",""); exists {
	  fmt.Fprintf(w, `<a href="/login/ADFS/">LOGIN to ADFS</a><br/>`)
        }
}

// shows info about authenticated user
func loggedinHandler(w http.ResponseWriter, r *http.Request, githubData string) {
        w.Header().Set("Cache-Control", "no-cache, private, max-age=0")
	if githubData == "" {
		// Unauthorized users get an unauthorized message
		fmt.Fprintf(w, "UNAUTHORIZED!")
		return
	}

	w.Header().Set("Content-type", "application/json")

	// Prettifying the json
	var prettyJSON bytes.Buffer
	// json.indent is a library utility function to prettify JSON indentation
	parserr := json.Indent(&prettyJSON, []byte(githubData), "", "\t")
	if parserr != nil {
		log.Panic("JSON parse error")
	}

	// Return the prettified JSON as a string
	fmt.Fprintf(w, string(prettyJSON.Bytes()))
}

// https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios#request-an-authorization-code
// construct URL to authorize into ADFS using proper OAuth2 Application
func adfsLoginHandler(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Cache-Control", "no-cache, private, max-age=0")
        adfs, _ := osLookupEnv("ADFS","")
        adfsClientID, _ := osLookupEnv("ADFS_CLIENT_ID","")
        redirectStr, _ := osLookupEnv("ADFS_REDIRECT_URI","http://localhost:8080/login/oauth2/code/adfs")
        scopes, _ := osLookupEnv("ADFS_SCOPE","openid allatclaims")

        // unique values for state and nonce
        stateStr := makeNonce()
        nonceStr := makeNonce()

        // construct authorize URL to ADFS
	redirectURL := fmt.Sprintf("https://%s/adfs/oauth2/authorize?resource=%s&response_type=code&client_id=%s&scope=%s&state=%s&redirect_uri=%s&nonce=%s",adfs,adfsClientID,adfsClientID,scopes,stateStr,redirectStr,nonceStr)
	fmt.Println(redirectURL)

	http.Redirect(w, r, redirectURL, 301)
}

// https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios#successful-response-2
// 'code' sent by the ADFS Authorization Server, up to us to decode embedded Access Token
func adfsCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	fmt.Println("code returned from AFS:",code)

	_,adfsAccessJSON := getADFSAccessTokenAndJSON(code)
	fmt.Println("adfsAccessJSON:",adfsAccessJSON)

	loggedinHandler(w, r, adfsAccessJSON)
}

// https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios#request-an-access-token
// trade code for Access Token
func getADFSAccessTokenAndJSON(code string) (string,string) {

        adfs, _ := osLookupEnv("ADFS","")
        clientID, _ := osLookupEnv("ADFS_CLIENT_ID","")
        clientSecret, _ := osLookupEnv("ADFS_CLIENT_SECRET","")
        redirectStr, _ := osLookupEnv("ADFS_REDIRECT_URI","http://localhost:8080/login/oauth2/code/adfs")
        tokenURL, _ := osLookupEnv("ADFS_TOKEN_URI","/adfs/oauth2/token")
        tokenURL = "https://" + adfs + tokenURL // prepend ADFS protocol and host
	fmt.Println("adfs tokenURL:",tokenURL)

        data := url.Values{}
        data.Set("grant_type", "authorization_code")
        data.Set("client_id", clientID)
        data.Set("client_secret", clientSecret)
        data.Set("code", code)
        data.Set("redirect_uri", redirectStr)

	req, reqerr := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()) )
	if reqerr != nil {
		log.Panic("Request creation failed", reqerr)
	}
	req.Header.Set("Accept", "application/json")

	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		log.Panic("Request failed",resperr)
	}

	respbody, _ := ioutil.ReadAll(resp.Body)

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
          log.Panic("unknown marshall failed",err)
        }
        fmt.Println("==BEGIN ALL DECODED FIELDS============")
        for k, v := range unknown {
          fmt.Println(k,":",v)
        }
        fmt.Println("==END ALL DECODED FIELDS============")
	//fmt.Println(ghresp.AccessToken)
	//fmt.Println("scope:",ghresp.Scope)


        // NOW decode just the AccessToken field, which is a signed JWT
        // https://stackoverflow.com/questions/45405626/how-to-decode-a-jwt-token-in-go
        // decode JWT token without verifying the signature
        var claims map[string]interface{} // generic map to store parsed token
        token, _ := jwt.ParseSigned(ghresp.AccessToken)
         _ = token.UnsafeClaimsWithoutVerification(&claims)
        fmt.Println("==BEGIN DECODED ACCESS TOKEN JWT============")
        for k, v := range claims {
          fmt.Println(k,":",v)
        }
        fmt.Println("==END DECODED ACCESS TOKEN JWT============")
        accessTokenJSON, err := json.Marshal(claims)
        if err != nil {
		log.Panic("JSON marshal of access token failed", err)
        }

	return ghresp.AccessToken, string(accessTokenJSON)
}

// https://docs.microsoft.com/en-us/azure/active-directory/develop/userinfo#calling-the-api
// our access token has custom claims so the resource in the access token is 'microsoft:identityserver:<client-id>'
// so we get 401 errors back from ADFS if trying to call the endpoint which only wants 'urn:microsoft:userinfo'
// the /adfs/userinfo endpoint only returns 'sub' anyway, so there is very little benefit
func getADFSData(accessToken string) string {
	return "{}"
/*

        adfs, _ := osLookupEnv("ADFS_USERINFO_URL","")
        userinfoURL = "https://" + adfs + "/adfs/userinfo?resource=urn:microsoft:userinfo"
	req, reqerr := http.NewRequest("POST", userinfoURL, nil)
	if reqerr != nil {
		log.Panic("call to ADFS userinfo failed")
	}

	authorizationHeaderValue := fmt.Sprintf("Bearer %s", accessToken)
	req.Header.Set("Authorization", authorizationHeaderValue)
	fmt.Println("HEADER Authorization:",authorizationHeaderValue)

	resp, resperr := http.DefaultClient.Do(req)
	if resperr != nil {
		log.Panic("Request failed")
	}

	respbody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(respbody)

	return string(respbody)
*/
}




func githubLoginHandler(w http.ResponseWriter, r *http.Request) {
	githubClientID := getGithubClientID()

	redirectURL := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s", githubClientID, "http://localhost:3000/login/github/callback")

	http.Redirect(w, r, redirectURL, 301)
}

func githubCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	githubAccessToken := getGithubAccessToken(code)

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

	clientID := getGithubClientID()
	clientSecret := getGithubClientSecret()

	requestBodyMap := map[string]string{"client_id": clientID, "client_secret": clientSecret, "code": code}
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

	return ghresp.AccessToken
}

func getGithubClientID() string {
	githubClientID, exists := osLookupEnv("GITHUB_CLIENT_ID","")
	if !exists {
		log.Fatal("Github Client ID not defined in .env file")
	}
	return githubClientID
}

func getGithubClientSecret() string {
	githubClientSecret, exists := osLookupEnv("GITHUB_CLIENT_SECRET","")
	if !exists {
		log.Fatal("Github Client Secret not defined in .env file")
	}
	return githubClientSecret
}

// get OS environment variable, have default value if non-existent
func osLookupEnv(key string,defaultValue string) (string,bool) {
	val, exists := os.LookupEnv(key)
        if exists {
          return val, true
        }else {
          if defaultValue == "" {
            return "", false
          }else {
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
