##  oauth2-client-app-golang ##

A GoLang implementation of an OAuth2/OIDC Client Application in a Authorization Code flow.

### Tested OAuth2/OIDC Authentiation Servers

* Windows 2019 ADFS
* Keycloak 19
* Okta

### Tested OAuth2 (non-OIDC) Authentiation Servers

* Github
* Spotify

### Detailed walk-throughs

* [Microsoft: configuring an Application Group for OAuth2/OIDC on ADFS 2019](https://fabianlee.org/2022/08/22/microsoft-configuring-an-application-group-for-oauth2-oidc-on-adfs-2019/)
* [Kubernetes: Keycloak IAM deployed into Kubernetes cluster for OAuth2/OIDC ](https://fabianlee.org/2022/09/10/kubernetes-keycloak-iam-deployed-into-kubernetes-cluster-for-oauth2-oidc/)

### OAuth2/OIDC Entities

![OAuth2/OIDC Entities](https://github.com/fabianlee/oauth2-client-app-golang/raw/main/diagrams/oauth2-oidc-entities.drawio.png)


Thanks to sharmarajdaksh for the original Client App implementation against the Github OAuth2 server.
https://github.com/sharmarajdaksh/github-oauth-go
