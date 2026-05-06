



echo -n "5adb152cfabbe6e5000715553aa654d0bae6e3495a74796cb4eda328f610a1a9" | gcloud secrets create paseto-secret \
  --data-file=- --project=quantchat-server

echo -n "machogrande" | gcloud secrets create db-pass \
  --data-file=- --project=quantchat-server

echo -n "redis://10.167.56.211:6379" | gcloud secrets create redis-url \
  --data-file=- --project=quantchat-server
