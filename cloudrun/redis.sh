#!/bin/bash
gcloud run deploy quantchat-server \
   --source . \
   --region us-central1 \
   --vpc-connector quantchat-connector \
   --set-env-vars "REDIS_HOST=10.167.56.211,REDIS_PORT=6379" \
   --add-cloudsql-instances quantchat-server:us-central1:quantchat
