#!/bin/bash

# 1. Get a PASETO token (login)
TOKEN=$(curl -s -X POST \
  https://api.kyberchar.com/validate_login \
  -H 'Content-Type: application/json' \
  -d '{"username":"tomw","password":"69ftelvis"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

ECHO "token $TOKEN"

# 2. Exchange for Firebase token
curl -X POST \
  https://quantchat-server-1078066473760.us-central1.run.app/firebase_token \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json'
