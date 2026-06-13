#!/bin/bash
# Run this after every Vault pod restart to restore k8s auth connectivity

echo "Configuring Kubernetes auth..."

TOKEN_REVIEWER_JWT=$(kubectl create token vault -n vault --duration=8760h)
K8S_CA=$(kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d)

kubectl exec -n vault vault-0 -- vault write auth/kubernetes/config \
  kubernetes_host="https://10.43.0.1:443" \
  kubernetes_ca_cert="$K8S_CA" \
  token_reviewer_jwt="$TOKEN_REVIEWER_JWT" \
  disable_iss_validation=true

echo "Done. Testing connectivity..."
kubectl exec -n vault vault-0 -- wget -qO- --no-check-certificate \
  https://10.43.0.1/healthz 2>&1
