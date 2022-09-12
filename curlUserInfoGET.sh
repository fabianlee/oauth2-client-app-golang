server="$1"

curl -k --location -X GET \
-H "Authorization: Bearer $JWT" \
"https://$server/oauth2/v1/userinfo"

