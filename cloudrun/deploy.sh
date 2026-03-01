#!/bin/bash
gcloud run deploy quantchat-server \
   --source . \
   --region us-central1 \
   --add-cloudsql-instances quantchat-server:us-central1:quantchat \
   --allow-unauthenticated \
   --set-env-vars "DB_USER=k8s,DB_PASS=machogrande,DB_NAME=e2e_chat_service,DB_HOST=/cloudsql/quantchat-server:us-central1:quantchat"
