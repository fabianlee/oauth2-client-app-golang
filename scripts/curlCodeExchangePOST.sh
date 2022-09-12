URL=https://keycloak.kubeadm.local/realms/myrealm/protocol/openid-connect/token
code="the code"
redirect_uri=http://localhost:8080/oidc_callback

curl -k --location --request POST "$URL" \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode "client_id=$CLIENT_ID" \
--data-urlencode "client_secret=$CLIENT_SECRET" \
--data-urlencode "code=$code" \
--data-urlencode "realm=myrealm" \
--data-urlencode "scope=openid" \
--data-urlencode "grant_type=authorization_code" \
--data-urlencode "redirect_uri=$redirect_uri"
