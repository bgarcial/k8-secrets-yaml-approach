# k8-secrets-yaml-approach

## SUMMARY
This is a basic test case where we can work with kubernetes secrets where we will evaluate the reasons behind the `base64` encoding approach implemented by default by Kubernetes is not a security measure since it is not an encryption process.
This is why a python approach is addressed to protect the secrets at the runtime execution from Azure DevOps avoiding to hardcode the `base64` representation (which can be easily decoded) on the repository projects.

This approach solution was used for a Kong database approach deployment, and along the way we have created an architecture deployment from azure cli, and checking how to get TLS encryption for a simple http hello world service using an opensource CA like [Let'sEncrypt](https://letsencrypt.org/) by using the Kong Ingress Controller functionality inside Kubernetes.
Having said this, we realised about the possibilities that Kong as a cloud native solution offers [via their plugin architectural approach](https://docs.konghq.com/hub/)

In this small case the following infrastructure resources were involved:
-	Vnets and subnet
-	AKS cluster
      - Helm package manager
      - Kong application deployment to interact with postgresql
-	Azure Database for PostgreSQL
      - PostgreSQL Firewall Rules (only traffic from Load balancer and Aks subnet is allowed)
-	An Standard Load Balancer
-	Public Ip addresses

All these workflow described is being executed by a release pipeline from Azure Dev

