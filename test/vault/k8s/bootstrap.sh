#!/bin/sh
# Creates the Kubernetes service accounts used by the kubernetes auth tests and writes their tokens,
# plus the cluster CA certificate, to /out (test/vault/k8s/generated on the host).
#   vault-reviewer  allowed to call the TokenReview API; Vault uses it to validate login tokens
#   duckdb          bound to the Vault role "duckdb"
#   other           a service account Vault must reject
set -eu

# k3s writes its kubeconfig for 127.0.0.1; reach it by its compose service name instead
sed 's#https://127.0.0.1:6443#https://k3s:6443#' /kube/kubeconfig.yaml > /tmp/kubeconfig
export KUBECONFIG=/tmp/kubeconfig

apply() {
	kubectl "$@" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
}
apply create serviceaccount vault-reviewer
apply create serviceaccount duckdb
apply create serviceaccount other
apply create clusterrolebinding vault-reviewer --clusterrole=system:auth-delegator \
	--serviceaccount=default:vault-reviewer

kubectl create token vault-reviewer --duration=24h > /out/reviewer.jwt
kubectl create token duckdb --duration=24h > /out/duckdb.jwt
kubectl create token other --duration=24h > /out/other.jwt
grep certificate-authority-data /tmp/kubeconfig | awk '{print $2}' | base64 -d > /out/ca.crt
chmod 644 /out/*

echo "Kubernetes service accounts and tokens created"
