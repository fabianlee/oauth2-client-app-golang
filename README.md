##  oauth2-client-app-golang ##

A GoLang implementation of an OAuth2/OIDC Client Application in a Authorization Code flow.

![OAuth2/OIDC Entities](https://github.com/fabianlee/oauth2-client-app-golang/raw/main/diagrams/oauth2-oidc-entities.drawio.png)

### Tested OIDC Authentiation Servers

* [Windows 2019 ADFS](https://fabianlee.org/2022/08/22/microsoft-configuring-an-application-group-for-oauth2-oidc-on-adfs-2019/)
* [Keycloak 19](https://fabianlee.org/2022/09/10/kubernetes-keycloak-iam-deployed-into-kubernetes-cluster-for-oauth2-oidc/)
* [Okta](https://developer.okta.com)

### Tested OAuth2 (non-OIDC) Authentiation Servers

* Github
* Spotify

### Detailed walk-throughs

* [Microsoft: configuring an Application Group for OAuth2/OIDC on ADFS 2019](https://fabianlee.org/2022/08/22/microsoft-configuring-an-application-group-for-oauth2-oidc-on-adfs-2019/)
* [Kubernetes: Keycloak IAM deployed into Kubernetes cluster for OAuth2/OIDC ](https://fabianlee.org/2022/09/10/kubernetes-keycloak-iam-deployed-into-kubernetes-cluster-for-oauth2-oidc/)

### Environment variables for ADFS

```
export AUTH_SERVER=win2k19-adfs1.fabian.lee
export AUTH_PROVIDER=adfs
export CLIENT_ID=<the oauth2 client id>
export CLIENT_SECRET=<the oauth2 client secret>
export SCOPE="openid allatclaims"

# default callback at /login/oauth2/code/adfs
```

### Environment variables for Keycloak

```
export AUTH_SERVER=keycloak.kubeadm.local
export AUTH_PROVIDER=keycloak
export CLIENT_ID=<the oauth2 client id>
export CLIENT_SECRET=<the oauth2 client secret>
export SCOPE="openid email profile"

export REALM=myrealm

# default callback at /oidc_callback
```

### Environment variables for okta

```
export AUTH_SERVER=dev-xxxxxx.okta.com
export AUTH_PROVIDER=okta
export CLIENT_ID=<the oauth2 client id>
export CLIENT_SECRET=<the oauth2 client secret>
export SCOPE="openid"

# default callback at /authorization-code/callback
```

### Environment variables for Github

```
export AUTH_SERVER=github.com
export AUTH_PROVIDER=github
export CLIENT_ID=<the oauth2 client id>
export CLIENT_SECRET=<the oauth2 client secret>
export SCOPE="openid"

# default callback at /login/github/callback
```

### Environment variables for Spotify

```
export AUTH_SERVER=accounts.spotify.com
export AUTH_PROVIDER=spotify
export CLIENT_ID=<the oauth2 client id>
export CLIENT_SECRET=<the oauth2 client secret>
export SCOPE="streaming"

# default callback at /login/oauth2/code/spotify
```

### Running as Docker container

```
# remove any older container runs
docker rm oauth2-client-app-golang

# run docker image locally, listening on localhost:8080
docker run -it --rm \
--name oauth2-client-app-golang \
--network host \
-p 8080:8080 \
-e AUTH_PROVIDER=$AUTH_PROVIDER \
-e AUTH_SERVER=$AUTH_SERVER \
-e CLIENT_ID=$CLIENT_ID \
-e CLIENT_SECRET=$CLIENT_SECRET \
-e SCOPE="$SCOPE" \
-e REALM="$REALM" \
fabianlee/oauth2-client-app-golang:1.0.0
```

### Running as local GoLang executable

```
go get
mkdir -p bin
CGO_ENABLED=0 go build -o bin/oauth2-client-app-golang
bin/oauth2-client-app-golang
```


Thanks to sharmarajdaksh for the original Client App implementation against the Github OAuth2 server.
https://github.com/sharmarajdaksh/github-oauth-go
