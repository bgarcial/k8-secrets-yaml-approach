# Write your commands here

echo 'Deploying Cert Manager'

echo "Login to azure from az cli tool"
az login --service-principal --username $(SERVICE_PRINCIPAL_CLIENT_ID) --password $(SERVICE_PRINCIPAL_CLIENT_SECRET) --tenant $(AZURE_TENANT_ID)

echo "Login to K8s azure cluster"
az aks get-credentials --resource-group $(RESOURCE_GROUP_NAME) --name $(KUBERNETES_CLUSTER_NAME)


helm repo add jetstack https://charts.jetstack.io
helm repo update

helm install \
  cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --version v0.14.1