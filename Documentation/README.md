## 1. INTRODUCTION / CONTEXT

There are some cases in Kubernetes when our application code needs access to secret information like credentials, tokens, etcetera; in order to do that its need to do. For example if we run a Wordpress site or any CMS platform, some components will need access to a database service, so they will need the right access tokens or username/password combination to get the data they need to view or manipulate.
It has to do with pass secret information into the applications (in this case the kong ingress controller image service) running under Kubernetes. For that purpose its provide the secret resource.

## 2. IDENTIFYING THE PROBLEM

When we work with secrets in Kubernetes, we realized that those values are injected to the application pods in an encoded way by using [`base64` encoding library](https://en.wikipedia.org/wiki/Base64).
The inconvenient with the use of this encoding process, is that we can decode them easily (it is a command passing as parameter the encoded value as we will see later on), so if someone knows how to decoding the `base64` values, that person/process/bot can get access to the real secret value.

Kubernetes uses the `base64` encoding representation internally when secrets are created.  Let's see [this small sample secret creation](https://kubernetes.io/docs/concepts/configuration/secret/#creating-a-secret-using-kubectl) on the fly by using `kubectl` tool:

```
kubectl create secret generic dev-db-secret --from-literal=username=devuser --from-literal=password='S!B\*d$zDsb'
secret/dev-db-secret created
```
- If we check this secret in detail the cluster, we can see the `username` and `password` values were encoded, the values are not the same. K8s using `base64` representation of them
```
kubectl get secret/dev-db-secret -o yaml
apiVersion: v1
data:
  password: UyFCXCpkJHpEc2I=
  username: ZGV2dXNlcg==
kind: Secret
metadata:
  creationTimestamp: "2020-04-08T07:41:24Z"
  name: dev-db-secret
  namespace: default
  resourceVersion: "8248"
  selfLink: /api/v1/namespaces/default/secrets/dev-db-secret
  uid: a50ec1c6-014a-4291-9f60-95251e9724fd
type: Opaque
```
If we decode those `base64` values, we can get the real values
```
# password
echo -n 'UyFCXCpkJHpEc2I=' | base64 --decode
S!B\*d$zDsb
---
# username
echo -n 'ZGV2dXNlcg==' | base64 --decode
devuser
```

---

### 2.1 Encoding data connection string by using `base64` representation values.

In a more practical sample, let's say we want to store the following sensitive data connection: `username`, `password`, `servername`(host) and `database_name` in K8s using a secret resource to connect to a database. So if we use a YAML file which will be handled by any control version system inside a project repository, the first that we do is encode the secret values using the `base64` representation. We don't want to have hardcoded the real values in our repository, even when we are dealing with private repositories.

- username
```
echo -n 'myusername@k8s-postgresql1' | base64
bXl1c2VybmFtZUBrOHMtcG9zdGdyZXNxbDE=
```

So is this outcome value `bXl1c2VybmFtZUBrOHMtcG9zdGdyZXNxbDE` which will be used inside kubernetes secrets yaml file to reference it inside the cluster.
The same for the other sensitive data:

- password

```
echo -n 'mypassword' | base64
bXlwYXNzd29yZA==
```
- Server name
```
echo -n 'myservername.postgres.database.cloudprovider.com' | base64
bXlzZXJ2ZXJuYW1lLnBvc3RncmVzLmRhdGFiYXNlLmNsb3VkcHJvdmlkZXIuY29t
```
- database
```
echo -n 'mydatabasename' | base64
bXlkYXRhYmFzZW5hbWU=
```

So, let's create a secret resource with these encoded values previously and look how are they stored in the etcd database, which is the key value storage that K8s use as a backing store for all cluster data.

- We have this  `pg-secrets.yaml` file with the previous encoded values:
```
apiVersion: v1
kind: Namespace
metadata:
  name: test
---
apiVersion: v1
kind: Secret
metadata:
  name: my-db-secrets
  namespace: test
type: Opaque
data:
  username: bXl1c2VybmFtZUBrOHMtcG9zdGdyZXNxbDE=
  password: bXlwYXNzd29yZA==
  host: bXlzZXJ2ZXJuYW1lLnBvc3RncmVzLmRhdGFiYXNlLmNsb3VkcHJvdmlkZXIuY29t
  database: bXlkYXRhYmFzZW5hbWU=
```
- We create the secret:
```
kubectl create -f pg-secrets.yaml
namespace/test created
secret/my-db-secrets created
```

- If we explore in detail this secret resource created:
```
kubectl get secret/my-db-secrets -o yaml -n test
apiVersion: v1
data:
  database: bXlkYXRhYmFzZW5hbWU=
  host: bXlzZXJ2ZXJuYW1lLnBvc3RncmVzLmRhdGFiYXNlLmNsb3VkcHJvdmlkZXIuY29t
  password: bXlwYXNzd29yZA==
  username: bXl1c2VybmFtZUBrOHMtcG9zdGdyZXNxbDE=
kind: Secret
metadata:
  creationTimestamp: "2020-04-08T07:31:59Z"
  name: my-db-secrets
  namespace: test
  resourceVersion: "7497"
  selfLink: /api/v1/namespaces/test/secrets/my-db-secrets
  uid: 9e59c2f1-1d5d-4db1-a7ea-1ff596f7c2f0
type: Opaque
```
So as we saw in the first literal secret creation sample, despite of apply `base64` representation, we can take those encoded values and decode them by using the following command:

```
# database
echo -n 'bXlkYXRhYmFzZW5hbWU=' | base64 --decode
mydatabasename
---
# host
echo -n 'bXlzZXJ2ZXJuYW1lLnBvc3RncmVzLmRhdGFiYXNlLmNsb3VkcHJvdmlkZXIuY29t' | base64 --decode
myservername.postgres.database.cloudprovider.com
---
# password
echo -n 'bXlwYXNzd29yZA==' | base64 --decode
mypassword
---
# username
echo -n 'bXl1c2VybmFtZUBrOHMtcG9zdGdyZXNxbDE=' | base64 --decode
myusername@k8s-postgresql1
```

So that we got here, is that we can get easily the secrets values. That is because secret values encoded in `base64` in secret manifest files (`.yaml`,`.txt`) **are not encrypted!**, they are simply encoded and although `base64` makes content unreadable to the human eye, it doesn't not encrypt it. As we see in the decoding process, this situation is effectively plain text to an attacker.


## 3. SOLUTION APPROACH ADDRESSED

Keeping in mind that could do exist many other approach solutions to deal with this problem (even maybe more optimals, and even under several different perspectives - K8s infrastructure security, programming, etc. - ) the propose one here is use python within specific beside operation activities context in this secrets exposition situation.
In order to pursue that, there are two important tools/libraries here which can help us:
- There is a [PyYAML library](https://pyyaml.org/wiki/PyYAMLDocumentation) which allow us to read YAML manifest files, retrieve specific attributes of it and execute specific actions on it.
The official repository of the previous link website is [this](https://github.com/yaml/pyyaml), it belongs to the YAML project and so far it is in constantly mainteinance activities by the community (if we see the latest recently commits)

- Using [argparse](https://docs.python.org/3/howto/argparse.html#introducing-positional-arguments) library to send the real secrets values as a positional arguments to the specific yaml atributes in our secret.

The goal here is pass the real secret values as a string positional arguments by defining specifics flags:values equivalences. And of course we will use of `base64` representation where the secrets will be injected to the K8s cluster

According to that it will be the pyhton script to pass the real secrets values as a string positional arguments:

```
import yaml
import base64
import argparse

class PostgresqlSecrets:

    def __init__(self):
        pass

    def set_secrets(self, file_name,
                    pg_username,
                    pg_password,
                    pg_host,
                    pg_database):
        print("secret_file: " + file_name)
        with open(file_name) as f:
            doc = yaml.safe_load(f)
        doc['data']['username'] = base64.b64encode(pg_username.encode('utf-8')).decode('utf-8')
        doc['data']['password'] = base64.b64encode(pg_password.encode('utf-8')).decode('utf-8')
        doc['data']['host'] = base64.b64encode(pg_host.encode('utf-8')).decode('utf-8')
        doc['data']['database'] = base64.b64encode(pg_database.encode('utf-8')).decode('utf-8')

        with open(file_name, 'w') as f:
            yaml.safe_dump(doc, f, default_flow_style=False)
        return

'''
The secrets from azure DevOps need to be passed in as positional arguments,
so the real values should be defined as a variable groups there and this
set_secrets function takes them and maps them to the specific YAML  doc[data][*.] attributes objects
'''

parser = argparse.ArgumentParser()
parser.add_argument('--PG_USERNAME', '-pg-username', help="Pass the username as an argument", type= str)
parser.add_argument('--PG_PASSWORD', '-pg-password', help="Pass the password as an argument", type= str)
parser.add_argument('--PG_HOST', '-pg-host', help="Pass the database server name as an argument", type= str)
parser.add_argument('--PG_DATABASE', '-pg-database', help="Pass the database name as an argument", type= str)
secrets = parser.parse_args()

kdb = PostgresqlSecrets()

# print("It is the username", secrets.PG_USERNAME)
# print("it's the passwd", secrets.PG_PASSWORD)
# print("it's the host", secrets.PG_HOST)
# print("it's the DATABASE", secrets.PG_DATABASE)

kdb.set_secrets("./pg-secrets.yaml",
            pg_username=secrets.PG_USERNAME,
            pg_password=secrets.PG_PASSWORD,
            pg_host=secrets.PG_HOST,
            pg_database=secrets.PG_DATABASE)
```

- Other useful thing about `argparse` module used is that it allows to make friendly command line interfaces by defining positional arguments required according to the context.
So if we check this script without execute it (by passing the `-h` flag), we can see the different arguments parsed in the script which acts as a small documentation about how to use them:

```
python set_pg_secrets.py -h
usage: set_pg_secrets.py [-h] [--PG_USERNAME PG_USERNAME] [--PG_PASSWORD PG_PASSWORD] [--PG_HOST PG_HOST]
                         [--PG_DATABASE PG_DATABASE]

optional arguments:
  -h, --help            show this help message and exit
  --PG_USERNAME PG_USERNAME, -pg-username PG_USERNAME
                        Pass the username as an argument
  --PG_PASSWORD PG_PASSWORD, -pg-password PG_PASSWORD
                        Pass the password as an argument
  --PG_HOST PG_HOST, -pg-host PG_HOST
                        Pass the database server name as an argument
  --PG_DATABASE PG_DATABASE, -pg-database PG_DATABASE
                        Pass the database name as an argument
```
That was exactly that was defined as an arguments to be passed.

- In order to execute a small test from a local terminal, let's take our `pg-secrets.yaml` and put fake equivalence values in the `username`, `password`, `host` and `database` secrets YAML attributes. These fake values will be that people will see hardcoded in the repository.

```
apiVersion: v1
kind: Secret
metadata:
  name: my-db-secrets
  namespace: test
type: Opaque
data:
  username: fake-username-to-be-stored-in-repository
  password: fake-password-to-be-stored-in-repository
  host: fake-server-name-to-be-stored-in-repository
  database: fake-database-name-to-be-stored-in-repository
```
- If we execute the python script from a local terminal passing the real values secrets as string positional arguments, we will see the secrets fake values will be replaced for the original ones:

```
python set_pg_secrets.py -pg-username bgarcial@k8s-postgresql1  -pg-password my-r34l-p455w0rd -pg-host k8s-postgresql1.postgres.database.azure.com -pg-database tst-db
secret_file: ./pg-secrets.yaml
```

![Replacing secrets values](https://cldup.com/oAD8Cer7S2.gif "Logo Title Text 1")

## 4. Kubernetes, Azure DevOps, PostgreSQL database and Hello World application service. Putting all together.

Let's approach to a practical real situation where we can take in advance of the topics we have discussed so far.
Let's suppose we have this small architecture deployment:

- Vnet - range 10.0.0.0/16 - 65534 hosts per subnet
  - Aks Subnet - range 10.0.1.0/24 - 254 hosts per subnet for AKS cluster.
- Kubernetes Paas Service
- PostgreSQL Paas service
- Hashicorp HTTP echo Hello World Application Service


##INCLUDE ARCHITECTURE DIAGRAM

### 4.1. Creating Infrastructure resources.

- Let's create the resource group for the Vnet and the Azure Kubernetes Service

```
az group create --name k8s-secrets-post-rg --location westeurope
```

- Creating Vnet and AksSubnet

```
az network vnet create --resource-group k8s-secrets-post-rg \
              --name myTestVnet \
              --address-prefix 10.0.0.0/16 \
              --subnet-name AksSubnet \
              --subnet-prefixes 10.0.1.0/24
```

- Getting the vnet subnet id where the AKS cluster will be created
```
az network vnet subnet list -g k8s-secrets-post-rg --vnet-name myTestVNet
[
 {
  "id": "/subscriptions/{$BGARCIAL_ARM_SUBSCRIPTION_ID}/resourceGroups/{$RESOURCE_GROUP_NAME}/providers/Microsoft.Network/virtualNetworks/{$VIRTUAL_NETWORK_NAME}/subnets/{$SUBNET_NAME}"
  }
]
```

- Creating the AKS cluster

The `SERVICE_PRINCIPAL_CLIENT_ID` and `SERVICE_PRINCIPAL_CLIENT_SECRET` variables referenced below, they belong to a service principal created previously. We associate this service principal to the AKS cluster and it will be used from Azure DevOps to create a service connection in order to authenticate to Azure APIs and perform actions over AKS cluster.

```
az aks create --name myTestApplication --resource-group k8s-secrets-post-rg --network-plugin azure \
                     --kubernetes-version 1.16.7 --service-cidr 100.0.0.0/16 \
                     --network-plugin azure \
                     --node-vm-size Standard_B2s \
                     --dns-name-prefix myTestApplication-dns \
                     --dns-service-ip 100.0.0.10 \
                     --docker-bridge-address 172.17.0.1/16 \
                     --location westeurope \
                     --node-count 2 \
                     --service-principal $SERVICE_PRINCIPAL_CLIENT_ID --client-secret $SERVICE_PRINCIPAL_CLIENT_SECRET \
                     --vnet-subnet-id /subscriptions/{$BGARCIAL_ARM_SUBSCRIPTION_ID}/resourceGroups/{$RESOURCE_GROUP_NAME}/providers/Microsoft.Network/virtualNetworks/{$VIRTUAL_NETWORK_NAME}/subnets/{$SUBNET_NAME}
```

- Creating resource group for Postgresql server.

```
az group create --name postgres-rg --location centralus
```

- Creating Postgres PaaS Server

```
az postgres server create -l centralus -g postgres-rg -n k8s-postgresql1 -u bgarcial -p $POSTGRESQL_PASSWORD --sku-name B_Gen5_1 --ssl-enforcement Disabled --backup-retention 10 --geo-redundant-backup Disabled --storage-size 20480 --tags "app=k8s" --version 10

```

- Creating Firewall rule to allow traffic from AksSubnet to Postgres Pass Service

```
az postgres server firewall-rule create -g postgres-rg -s k8s-postgresql1 -n allowAksSubnetIprange --start-ip-address 10.0.1.0 --end-ip-address 10.0.1.255
```

- Creating Firewall rule to allow traffic from my HomeIpAddress to Postgres Pass Service

```
az postgres server firewall-rule create -g postgres-rg -s k8s-postgresql1 -n allowHomeIpAddress --start-ip-address 217.105.19.231 --end-ip-address 217.105.19.231

```

- Creating postgres database to be used to connect from Azure Kubernetes service.

```
az postgres db create -g postgres-rg -s k8s-postgresql1 -n kong_tst
```
Here, the previous user defined in the database server creation is the owner of this database.


### 4.2. Configuring Azure DevOps.

We will create a release pipeline in order to perform some actions over the AKS cluster. So assuming that we already import the repository ([from Github in this case](https://github.com/bgarcial/k8-secrets-yaml-approach)) having previously the Github service connection to do it we have this stage environment with the artifact created:

![Setting Azure DevOps Artifact](https://cldup.com/RBwaTU2O4t.png "Logo Title Text 1")

We also have created previously the Azure Resource Manager Connection (subscription scope) by using the Service Principal credentials used in the AKS cluster creation previously.

![Setting Azure Resource Manager connection](https://cldup.com/GjBsCx5Lbp.png "Logo Title Text 1")



### 4.3 Building the release pipeline

We will divide the release pipeline in three (maybe 4) different sections by using agents.


#### 4.3.1 Deploying a simple HTTP K8s Hello world service application

This is the first agent, a hello world namespace will be created here to deploy the application inside it.
We will use this [http-echo service from hashicorp](https://github.com/hashicorp/http-echo) to deploy a basic "Hello World" message. It will simulate our application service taking [a public available docker image](https://hub.docker.com/r/hashicorp/http-echo/).

We have the **service - deployment** couple in the following YAML manifest file:
```
apiVersion: v1
kind: Service
metadata:
  name: echo
spec:
  ports:
    - port: 80
      targetPort: 5678
  selector:
    app: echo
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
spec:
  selector:
    matchLabels:
      app: echo
  replicas: 2
  template:
    metadata:
      labels:
        app: echo
    spec:
      containers:
        - name: echo
          image: hashicorp/http-echo
          args:
            - "-text=Hello World. These are K8s, kong-ingress-controller, postgress and cert-manager"
          ports:
            - containerPort: 5678
            # It will forward traffic to containerPort

```
Having this file in our repository, we will deploy the Hello World service from azure devops


Since we are using an existing YAML file to do that, we have to create a new Kubernetes service connection

![Setting Kubernetes Service connection](https://cldup.com/DEOUdYpRNx.png "Setting Kubernetes Service connection")

So we add a Deploy to Kubernetes task in the release pipeline choosing the Kubernetes service connection created previously:

![Adding Deploy Kubernetes task](https://cldup.com/Op_VGKC0Od.png "Adding Deploy Kubernetes task")

And we can see that the echo http service was deployed succesfully

![Hello World Service deployed into AKS](https://cldup.com/a28okN85Kp.png "Hello World Service deployed into AKS")

- If we check the `hello-world` namespace in relation to the k8s resources created, we can see:

```
kubectl get deploy,pods,service,replicasets -n hello-world
NAME                   READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/echo   2/2     2            2           84s

NAME                        READY   STATUS    RESTARTS   AGE
pod/echo-7dc4c66668-6tmfk   1/1     Running   0          84s
pod/echo-7dc4c66668-cqkx7   1/1     Running   0          84s

NAME           TYPE        CLUSTER-IP    EXTERNAL-IP   PORT(S)   AGE
service/echo   ClusterIP   100.0.12.24   <none>        80/TCP    84s

NAME                              DESIRED   CURRENT   READY   AGE
replicaset.apps/echo-7dc4c66668   2         2         2       84s
```

- Even we can see the Hello World service up and running inside the cluster without be published, by performing a port-forwarding action from the 8002 local port to the 5678 http-echo port service defined.

```
kubectl port-forward pod/echo-7dc4c66668-6tmfk 8002:5678 -n hello-world
Forwarding from 127.0.0.1:8002 -> 5678
Forwarding from [::1]:8002 -> 5678
Handling connection for 8002
```
So if we go to http://localhost:8002 we can see the service up and running

![Hello World Service up and running - K8s port-forward](https://cldup.com/4oa6XPup8n.png "Hello World Service up and running - K8s port-forward")


### 4.4 Deploying Kong Application service using PostgreSQL and secrets protection

We want to use [Kong](https://github.com/Kong/kong), which allow to do many important security, operational and communication processes, it is considered as a cloud navite product which acts as an Application Gateway, it works with microservices, it securize APIs access by multiple authentication methods (basic, tokens, AAD, LDAP), between many other things more by implementing plugins functionality.

Kong will be used in this scenario **only as an [ingress controller](https://konghq.com/solutions/kubernetes-ingress/)** inside our kubernetes cluster to publish the http hello world service and get TLS encryption with cert-manager.

We will deploy Kong using its official [helm chart](https://hub.helm.sh/charts/stable/kong) and along the way we will see the interaction with PostgreSQL.

Please keep in mind update the kong version in the `helm install stable/kong` command executed here. The helm chart is constantly updated.

Since we will use kong as ingress controller, we will deploy it as a Load Balancer service inside Kubernetes so when we requested it a real load balancer from the cloud provider of choice (Azure) is automatically attached.
Due to this we will have to create in advance [a public IP address to be used by the Kong Load Balancer Service](https://docs.microsoft.com/en-us/azure/aks/ingress-static-ip#create-an-ingress-controller).

- **Getting the resource group name of the AKS cluster.**
This name is a long internal name which Azure create when we create an AKS. We need to get it to the static public IP address creation process, since we need that public ip and the AKS share the same resource group.
```
az aks show --resource-group k8s-secrets-post-rg --name myTestApplication --query nodeResourceGroup -o tsv
MC_k8s-secrets-post-rg_myTestApplication_westeurope
```

- **Creating the Static public ip address to be associated with Kong Load Balancer**
```
az network public-ip create --resource-group MC_k8s-secrets-post-rg_myTestApplication_westeurope --name kongIngressControllerAKSPublicIP --sku Standard --allocation-method static --query publicIp.ipAddress -o tsv
51.138.45.137
```
So a new public static ip address was created in Azure and it will be used by Kong Ingress Controller.
In addition, this IP addres should be used as a entry when we want to associate our hello world service to a domain name. We will do it later.

![Public IP](https://cldup.com/NODAQ8PkUK.png "Public IP")


### 4.4.1 Deploying Kong

We will use [helm](https://helm.sh/) as a package manager tool to install applications on kubernetes cluster

- **Installing and configuring Helm v3.1.2 version**
In this first step via bash task helm will be downloaded, unpacked, and the main kubernetes chart storage repository will be added in order to get applications to be deployed with helm.

![Configuring helm](https://cldup.com/2yYUa177Nr.png "Configuring helm")

The complete script to perform this task can be accesses [here](https://github.com/bgarcial/k8-secrets-yaml-approach/blob/master/release-pipeline-tasks/configuringHelm.sh)

- **Adding kong chart repository to helm index charts**

[The following task](https://github.com/bgarcial/k8-secrets-yaml-approach/blob/master/release-pipeline-tasks/addingKongHelmChartRepository.sh) will be add kong chart to our local helm index repositories.

![Adding kong chart repository](https://cldup.com/_y1OZDEN0H.png "Adding kong chart repository")


- **Install python 3.8 on the Azure DevOps agent**

As we have seeing, is time to use the python script inside the release pipeline so the first task here is make python available for azure devops


![Install python 3.8 on the Azure DevOps agent](https://cldup.com/6tI-zC-hQq.png "Install python 3.8 on the Azure DevOps agent")


- **Install pyyaml library with using pip package manager**


![Install pyyaml library](https://cldup.com/jlt8GS46Iv.png "Install pyyaml library")


- **Executing python script to pass the real PosgreSQL secrets connection as string positional arguments**.

Here we will use the script to pass the real postgres secrets connection to the YAML file that will be executed on the kubernetes cluster.

The first thing is get ready the `kong_pg_secrets.yaml` file with fake values, because the idea is not to have base64 real encoding values, neither directly real values. So this is the content of that YAML file

We will use the `fake value` string to get its base64 representation:
```
echo -n 'fake-value' | base64
ZmFrZS12YWx1ZQ==
```

We take this value to be included in the `kong_pg_secrets.yaml` file. Is over this file  which [the python script will call to execute the replacing secrets values for the real ones](https://github.com/bgarcial/k8-secrets-yaml-approach/blob/087ff0e0129601d293caa10e3f09e3b066829fad/set_pg_secrets.py#L47), passing them as string postional arguments

```
apiVersion: v1
kind: Secret
metadata:
  name: kong-pg-secrets
  namespace: kong
type: Opaque
data:
  username: ZmFrZS12YWx1ZQ==
  password: ZmFrZS12YWx1ZQ==
  host: ZmFrZS12YWx1ZQ==
  database: ZmFrZS12YWx1ZQ==
```

Now the python script task should be created, but we have to create before as a variable groups in order to store the real secrets for PostgreSQL connection

![PostgreSQL db secrets variable group](https://cldup.com/TCS1gNYenh.png "PostgreSQL db secrets variable group")

So these `PG_HOST_SERVER_NAME` `PG_KONG_DATABASE_NAME`, `PG_PASSWORD`, `PG_USERNAME` variables will be referenced from the python script execution task of this way:

![Python script task](https://cldup.com/VRKOaBd4o9.png "Python script task")

- The following tasks will be to create a `kong` namespace and the [kong-pg-secrets resource inside kubernets](https://github.com/bgarcial/k8-secrets-yaml-approach/blob/master/kong_pg_secrets.yaml#L4)
Is in this task where the real secrets will be injected because of the python execution previous task

![Injecting PgSQL real secrets](https://cldup.com/jdfHhvMH-H.png "Injecting PgSQL real secrets")


- **Deploying Kong**

This is another bash task where kong will be installed inside Kubernetes
Notice that we have to use the Service principal data to sign in to Azure, in order to get the aks credentials cluster and reach the cluster with `helm install kong ...` command.

So before to execute this task, 4 new variables should be created:


![Creating new environment variables](https://cldup.com/FY7qp3Xaiy.png "Creating new environment variables")

This is the Kong deployment task.

![Injecting PgSQL real secrets](https://cldup.com/UE2l07xfpI.png "Injecting PgSQL real secrets")

So when we execute the release pipeline we got:

- Checking the python execution script task

We can see here the real secrets values defined above in the variables are being passed as string positional arguments now and the secret was created using their base64 representation.

![Checking the python execution script task](https://cldup.com/6t_MNZsn8n.png "Checking the python execution script task")

![Checking the python execution script task](https://cldup.com/zpiTMM-CCi.png "Checking the python execution script task")

- Checking kong helm installation task
So we see that kong was installed now,


![Checking kong helm installation task](https://cldup.com/IoaPdiRNZM.png "Checking kong helm installation task")

If we check the cluster, we can see the kong namespace something like this:

We can see the public ip address created before as an external ip, it is the ip address for kong as an ingress controller inside Kubernetes.

We can also see the `kong-pg-secrets` created and a job called `kong-init-migrations` executed via the `pod/kong-1586506832-kong-init-migrations-bv9hg` pod completed. Is this job and this pod who are in charge to perform the connection with PostgreSQL.

![Kong namespace](https://cldup.com/SpfBmAgtVA.png "Kong Namespace")

---
**IMPORTANT**
iF we see that the kong migrations job and pod is not complete,
```
NAME                                             READY   STATUS             RESTARTS   AGE
pod/kong-1586378371-kong-569dbd78b8-bzzft        0/2     Init:0/1           0          3m12s
pod/kong-1586378371-kong-init-migrations-vv9kj   0/1     CrashLoopBackOff   4          3m12s
```
---

Check the migration pod:
```
kubectl logs pod/kong-1586418466-kong-init-migrations-qlslm -n kong                     Thu Apr  9 09:48:29 2020
Error: [PostgreSQL error] failed to retrieve PostgreSQL server_version_num: FATAL: no pg_hba.conf entry for host "51.138.54.63", user "bgarcial", database "kong_tst", SSL on
```

- We add the  `51.138.54.63`to the postgres firewall rules and now is running

```
az postgres server firewall-rule create -g postgres-rg -s k8s-postgresql1 -n allow --start-ip-address 51.138.54.63 --end-ip-address 51.138.54.63
```
That Ip address was created by the Load Balancer generated by Kong deployment, so when the kong pod want to communicate with PostgreSQL database, the request has to come across this Standard Load Balancer created, to go to the Postgres, so this ip address is used by the load balancer outbound rules, since the traffic comes from Kubernetes towards outside, since the PostgreSQL database is not part of the Vnet environment.

![Load Balancer IP address Outbound rule](https://cldup.com/Edvj_MK4IW.png "Load Balancer IP address Outbound rule")

---

### 4.4.2 Checking Postgres Server Database

So according to the previous steps, a new database in postgres must be created, the kong database which will manage different topics like certificates, credentials, services, etceters

![Kong Database](https://cldup.com/rib1MYdh9W.png "Load Balancer IP address Outbound rule")

In that way we've manage to connect from Kubernetes to a PaaS service database and protectint those secrets credentials used in the connection in order to its doesn't be exposed.

Now we can check kong environment by doing a port-forward inside our k8s cluster

```
kubectl port-forward pod/kong-1586506832-kong-6dbf45cfbc-r6gpb 8003:8000 -n kong            Fri Apr 10 13:04:22 2020
Forwarding from 127.0.0.1:8003 -> 8000
Forwarding from [::1]:8003 -> 8000
```
If we go to http://localhost:8003/ we can interact with the Kong Api Server

![Kong API](https://cldup.com/eEnKZIdpgt.png "Kong API")

But even we don't need to to port-forwarding, since we install kong in Load Balancer mode, we can type the static ip address created before to it in a browser and we got the same API web interface:

![Kong API](https://cldup.com/U7gtjWFXJr.png "Kong API")



### 5. Getting HTTPS for Hello World HTTP Application

We want to use the Hashicorp hello world service container included before, so we want to get a proper domain for it, and also get https protocol or tls encryption. To pursue this, we will use [cert-manager](https://cert-manager.io/docs/installation/kubernetes/), which is an X.509 certificate manager for Kubernetes. We will get certificates for the domain hello-world.bgarcial.me by creating an A record for it pointing to the Kong Load Balancer ip address

![Creating A record](https://cldup.com/AO9LYoFjxb.png "Creating A record")

#### 5.1 Deploying Cert Manager from Azure DevOps

We will deploy cert-manager with helm, so we have to create similar tasks to the Kong deployment such as:

- Create namespace cert-manager
- download and configure helm inside the new agent created

- We also install Cert Manager CRDs via kubectl task deploying this command:
```
kubectl apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/v0.14.1/cert-manager.crds.yaml`
```
- And we deploy cert-manager [in a bash task](https://github.com/bgarcial/k8-secrets-yaml-approach/blob/master/release-pipeline-tasks/deployingCertManager.sh) in Azure DevOps

![Deploying cert manager](https://cldup.com/CvHL7pAnNd.png "Deploying cert manager")


According to that if we check in our cluster, a new cert-manager resources were created:


![Deploying cert manager](https://cldup.com/8YlkwMNMhB.png "Deploying cert manager")

![Deploying cert manager](https://cldup.com/SrBAQ8S8nf.png "Deploying cert manager")

#### 5.2 Getting HTTPs for the Hashicorp Hello World service.

To get HTTPS Cluster Issuers will be created in order to communicate with Let'sEncrypt ACME CA.
So these Cluster issuers will be created [for staging and production environment here](https://github.com/bgarcial/k8-secrets-yaml-approach/tree/master/CertManager), to be called by K8s azure devops tasks:


![Cluster issuers](https://cldup.com/FMWQl3fDr4.png "Cluster issuers")

We can see those staging and production cluster issuer were created:

![Cluster issuers](https://cldup.com/TaoDc2mUVO.png "Cluster issuers")

- **Creating Hello World application Ingress resource to get https**

We have to create an Ingress Resource in order to make interact kong, Cert-Manager and the Cluster Issues.
So this ingress resource who interacts with Production Cluster Issuer, will be executed from azure devops
```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  annotations:
    # add an annotation indicating the issuer to use.
    cert-manager.io/cluster-issuer: letsencrypt-prod
    kubernetes.io/ingress.class: kong
  name: echo-site-ingress
  namespace: hello-world
spec:
  rules:
  - host: hello-world.bgarcial.me
    http:
      paths:
      - backend:
          serviceName: echo
          servicePort: 80
        path: /
  tls: # < placing a host in the TLS config will indicate a cert should be created
  - hosts:
    - hello-world.bgarcial.me
    secretName: letsencrypt-prod
```
The `serviceName` attribute value is `echo` because that was the [service name assigned](https://github.com/bgarcial/k8-secrets-yaml-approach/blob/master/http-echo.yaml#L4)

![Creating Ingress](https://cldup.com/4zEGVwOUWB.png "Creating Ingress")

The outcome of this task is that the ingress was created and also a set of secrets


![Creating Ingress](https://cldup.com/nGk9P-9UZE.png "Creating Ingress")


If we inspect the logs on kong pod, we can see it is taking the request to be redirected to cert-manager because of the ingress execution:

```
kubectl logs pod/kong-1586506832-kong-6dbf45cfbc-r6gpb -n kong -c ingress-controller -f


E0410 12:16:10.347038       1 parser.go:1174] error finding a certificate in 'hello-world/letsencrypt-staging': parsing TLS key-pair in secret 'hello-world/letsencrypt-staging': tls: failed to find any PEM data in certificate input
I0410 12:16:14.179597       1 kong.go:66] successfully synced configuration to Kong
I0410 12:16:21.583153       1 kong.go:66] successfully synced configuration to Kong
I0410 12:21:25.474337       1 kong.go:57] no configuration change, skipping sync to Kong
I0410 12:21:28.807359       1 kong.go:57] no configuration change, skipping sync to Kong
I0410 12:21:32.141046       1 kong.go:57] no configuration change, skipping sync to Kong
E0410 12:27:14.697595       1 parser.go:1169] error fetching certificate 'hello-world/letsencrypt-prod': Secret hello-world/letsencrypt-prod not found
I0410 12:27:22.955790       1 kong.go:66] successfully synced configuration to Kong
E0410 12:27:22.956063       1 parser.go:1174] error finding a certificate in 'hello-world/letsencrypt-prod': parsing TLS key-pair in secret 'hello-world/letsencrypt-prod': tls: failed to find any PEM data in certificate input
I0410 12:27:28.460214       1 kong.go:66] successfully synced configuration to Kong
```

If we inspect cert-manager pod we can see that the http challenge is generated and accepted, also a certificate order is created, finalized and executed to Letsencrypt as a Certificate Signing Request

```
kubectl logs pod/cert-manager-579d48dff8-rkcn7 -n cert-manager -f


I0410 12:27:18.578229       1 pod.go:58] cert-manager/controller/challenges/http01/selfCheck/http01/ensurePod "msg"="found one existing HTTP01 solver pod" "dnsName"="hello-world.bgarcial.me" "related_resource_kind"="Pod" "related_resource_name"="cm-acme-http-solver-zwfc9" "related_resource_namespace"="hello-world" "resource_kind"="Challenge" "resource_name"="letsencrypt-prod-4090390416-948640117-393021107" "resource_namespace"="hello-world" "type"="http-01"
I0410 12:27:18.578323       1 service.go:43] cert-manager/controller/challenges/http01/selfCheck/http01/ensureService "msg"="found one existing HTTP01 solver Service for challenge resource" "dnsName"="hello-world.bgarcial.me" "related_resource_kind"="Service" "related_resource_name"="cm-acme-http-solver-x685t" "related_resource_namespace"="hello-world" "resource_kind"="Challenge" "resource_name"="letsencrypt-prod-4090390416-948640117-393021107" "resource_namespace"="hello-world" "type"="http-01"

.
.
.
0410 12:27:28.493355       1 ingress.go:91] cert-manager/controller/challenges/http01/selfCheck/http01/ensureIngress "msg"="found one existing HTTP01 solver ingress" "dnsName"="hello-world.bgarcial.me" "related_resource_kind"="Ingress" "related_resource_name"="cm-acme-http-solver-2j57j" "related_resource_namespace"="hello-world" "resource_kind"="Challenge" "resource_name"="letsencrypt-prod-4090390416-948640117-393021107" "resource_namespace"="hello-world" "type"="http-01"
I0410 12:27:38.739856       1 sync.go:337] cert-manager/controller/challenges/acceptChallenge "msg"="accepting challenge with ACME server" "dnsName"="hello-world.bgarcial.me" "resource_kind"="Challenge" "resource_name"="letsencrypt-prod-4090390416-948640117-393021107" "resource_namespace"="hello-world" "type"="http-01"
I0410 12:27:38.739896       1 logger.go:90] Calling AcceptChallenge
I0410 12:27:38.897610       1 sync.go:354] cert-manager/controller/challenges/acceptChallenge "msg"="waiting for authorization for domain" "dnsName"="hello-world.bgarcial.me" "resource_kind"="Challenge" "resource_name"="letsencrypt-prod-4090390416-948640117-393021107" "resource_namespace"="hello-world" "type"="http-01"
I0410 12:27:38.897638       1 logger.go:117] Calling WaitAuthorization
I0410 12:27:40.272232       1 controller.go:144] cert-manager/controller/challenges "msg"="finished processing work item" "key"="hello-world/letsencrypt-prod-4090390416-948640117-393021107"
I0410 12:27:40.273429       1 controller.go:138] cert-manager/controller/challenges "msg"="syncing item" "key"="hello-world/letsencrypt-prod-4090390416-948640117-393021107"
I0410 12:27:40.273671       1 controller.go:138] cert-manager/controller/orders "msg"="syncing item" "key"="hello-world/letsencrypt-prod-4090390416-948640117"
I0410 12:27:40.273793       1 logger.go:144] Calling HTTP01ChallengeResponse
I0410 12:27:40.273839       1 sync.go:166] cert-manager/controller/orders "msg"="All challenges are in a final state, updating order state" "resource_kind"="Order" "resource_name"="letsencrypt-prod-4090390416-948640117" "resource_namespace"="hello-world"
.
.
.
I0410 12:27:40.507627       1 logger.go:144] Calling HTTP01ChallengeResponse
I0410 12:27:40.507680       1 sync.go:146] cert-manager/controller/orders "msg"="Finalizing Order as order state is 'Ready'" "resource_kind"="Order" "resource_name"="letsencrypt-prod-4090390416-948640117" "resource_namespace"="hello-world"
I0410 12:27:40.507695       1 logger.go:81] Calling FinalizeOrder
I0410 12:27:40.555199       1 controller.go:144] cert-manager/controller/certificaterequests-issuer-acme "msg"="finished processing work item" "key"="hello-world/letsencrypt-prod-4090390416"
I0410 12:27:40.555382       1 controller.go:138] cert-manager/controller/certificaterequests-issuer-vault "msg"="syncing item" "key"="hello-world/letsencrypt-prod-4090390416"
I0410 12:27:40.555555       1 controller.go:138] cert-manager/controller/certificaterequests-issuer-acme "msg"="syncing item" "key"="hello-world/letsencrypt-prod-4090390416"
I0410 12:27:40.556002       1 acme.go:201] cert-manager/controller/certificaterequests-issuer-acme/sign "msg"="acme Order resource is not in a ready state, waiting..." "related_resource_kind"="Order" "related_resource_name"="letsencrypt-prod-4090390416-948640117" "related_resource_namespace"="hello-world" "resource_kind"="CertificateRequest" "resource_name"="letsencrypt-prod-4090390416" "resource_namespace"="hello-world"

.
.
.

I0410 12:27:41.313009       1 acme.go:189] cert-manager/controller/certificaterequests-issuer-acme/sign "msg"="certificate issued" "related_resource_kind"="Order" "related_resource_name"="letsencrypt-prod-4090390416-948640117" "related_resource_namespace"="hello-world" "resource_kind"="CertificateRequest" "resource_name"="letsencrypt-prod-4090390416" "resource_namespace"="hello-world"
I0410 12:27:41.313187       1 conditions.go:189] Found status change for CertificateRequest "letsencrypt-prod-4090390416" condition "Ready": "False" -> "True"; setting lastTransitionTime to 2020-04-10 12:27:41.31318328 +0000 UTC m=+5001.310897807
I0410 12:27:41.329226       1 controller.go:138] cert-manager/controller/challenges "msg"="syncing item" "key"="hello-world/letsencrypt-prod-4090390416-948640117-393021107"
I0410 12:27:41.330232       1 controller.go:144] cert-manager/controller/orders "msg"="finished processing work item" "key"="hello-world/letsencrypt-prod-4090390416-948640117"
I0410 12:27:41.330309       1 controller.go:138] cert-manager/controller/orders "msg"="syncing item" "key"="hello-world/letsencrypt-prod-4090390416-948640117"
I0410 12:27:41.330485       1 sync.go:102] cert-manager/controller/orders "msg"="Order has already been completed, cleaning up any owned Challenge resources" "resource_kind"="Order" "resource_name"="letsencrypt-prod-4090390416-948640117" "resource_namespace"="hello-world"

.
.
.
I0410 12:27:41.346776       1 sync.go:386] cert-manager/controller/certificates "msg"="validating existing CSR data" "related_resource_kind"="CertificateRequest" "related_resource_name"="letsencrypt-prod-4090390416" "related_resource_namespace"="hello-world" "resource_kind"="Certificate" "resource_name"="letsencrypt-prod" "resource_namespace"="hello-world"
I0410 12:27:41.346912       1 sync.go:464] cert-manager/controller/certificates "msg"="CertificateRequest is in a Ready state, issuing certificate..." "related_resource_kind"="CertificateRequest" "related_resource_name"="letsencrypt-prod-4090390416" "related_resource_namespace"="hello-world" "resource_kind"="Certificate" "resource_name"="letsencrypt-prod" "resource_namespace"="hello-world"

```

Those certificates and orders are reflected in the cluster here:


![Order and certificate](https://cldup.com/ukwTbgrnvd.png "Order and certificate")



So we can check the validated order

```
kubectl describe order.acme.cert-manager.io/letsencrypt-prod-4090390416-948640117 -n hello-world
Name:         letsencrypt-prod-4090390416-948640117
Namespace:    hello-world
Labels:       <none>
Annotations:  cert-manager.io/certificate-name: letsencrypt-prod
              cert-manager.io/private-key-secret-name: letsencrypt-prod
API Version:  acme.cert-manager.io/v1alpha3
Kind:         Order
Metadata:
  Creation Timestamp:  2020-04-10T12:27:15Z
  Generation:          1
  Owner References:
    API Version:           cert-manager.io/v1alpha2
    Block Owner Deletion:  true
    Controller:            true
    Kind:                  CertificateRequest
    Name:                  letsencrypt-prod-4090390416
    UID:                   b5499ce9-171f-4607-bf45-89a91756fd43
  Resource Version:        280744
  Self Link:               /apis/acme.cert-manager.io/v1alpha3/namespaces/hello-world/orders/letsencrypt-prod-4090390416-948640117
  UID:                     c9dcf796-1355-494c-821d-47137d39925e
Spec:
  Csr:
  Dns Names:
    hello-world.bgarcial.me
  Issuer Ref:
    Group:  cert-manager.io
    Kind:   ClusterIssuer
    Name:   letsencrypt-prod
Status:
  Authorizations:
    Challenges:
      Token:     DbSe9ABM8gpYo0LRQCxqczYE1k9o8S_J7A6UK_E_G3I
      Type:      http-01
      URL:       https://acme-v02.api.letsencrypt.org/acme/chall-v3/3875681065/rX1Guw
      Token:     xxxx
      Type:      dns-01
      URL:       https://acme-v02.api.letsencrypt.org/acme/chall-v3/3875681065/SCEORg
      Token:     DbSe9ABM8gpYo0LRQCxqczYE1k9o8S_J7A6UK_E_G3I
      Type:      tls-alpn-01
      URL:       https://acme-v02.api.letsencrypt.org/acme/chall-v3/3875681065/_mjaXA
    Identifier:  hello-world.bgarcial.me
    URL:         https://acme-v02.api.letsencrypt.org/acme/authz-v3/3875681065
    Wildcard:    false
  Certificate: xxxxx
  Finalize URL:  https://acme-v02.api.letsencrypt.org/acme/finalize/83036026/2954591460
  State:         valid
  URL:           https://acme-v02.api.letsencrypt.org/acme/order/83036026/2954591460
Events:
  Type    Reason    Age   From          Message
  ----    ------    ----  ----          -------
  Normal  Created   13m   cert-manager  Created Challenge resource "letsencrypt-prod-4090390416-948640117-393021107" for domain "hello-world.bgarcial.me"
  Normal  Complete  13m   cert-manager  Order completed successfully
```


And the certificate

```
kubectl describe certificate.cert-manager.io/letsencrypt-prod -n hello-world    21.2m  Fri Apr 10 14:39:41 2020
Name:         letsencrypt-prod
Namespace:    hello-world
Labels:       <none>
Annotations:  <none>
API Version:  cert-manager.io/v1alpha3
Kind:         Certificate
Metadata:
  Creation Timestamp:  2020-04-10T12:27:14Z
  Generation:          1
  Owner References:
    API Version:           extensions/v1beta1
    Block Owner Deletion:  true
    Controller:            true
    Kind:                  Ingress
    Name:                  echo-site-ingress
    UID:                   35a365bc-5578-4aa2-ba8a-5d3d11e53b69
  Resource Version:        280750
  Self Link:               /apis/cert-manager.io/v1alpha3/namespaces/hello-world/certificates/letsencrypt-prod
  UID:                     3e9b7fd6-f02e-497e-ab75-c28b5ff6bf50
Spec:
  Dns Names:
    hello-world.bgarcial.me
  Issuer Ref:
    Group:      cert-manager.io
    Kind:       ClusterIssuer
    Name:       letsencrypt-prod
  Secret Name:  letsencrypt-prod
Status:
  Conditions:
    Last Transition Time:  2020-04-10T12:27:41Z
    Message:               Certificate is up to date and has not expired
    Reason:                Ready
    Status:                True
    Type:                  Ready
  Not After:               2020-07-09T11:27:40Z
Events:
  Type    Reason        Age   From          Message
  ----    ------        ----  ----          -------
  Normal  GeneratedKey  12m   cert-manager  Generated a new private key
  Normal  Requested     12m   cert-manager  Created new CertificateRequest resource "letsencrypt-prod-4090390416"
  Normal  Issued        12m   cert-manager  Certificate issued successfully
```


At this point we can check the kong database, and we can see:

- Hashicorp http echo service

![Hello World service](https://cldup.com/TcWtosplMR.png "Hello World service")

-  The route created internally to reach the service

![Hello World service](https://cldup.com/elwT2zhYlI.png "Hello World service")

- The complete certificate that we got from Let'sEncrypt CA

![Hello World service certificate](https://cldup.com/ImgBaRIOsl.png "Hello World service certificate")

- The ip address used by the service to get up and running in the target table

![pods ip addressess](https://cldup.com/aj_gNI7iMq.png "pods ip addressess")
In this case we are talking at kubernetes level, so those ip addresses belong to the pods where the echo http hello world service is running. Those are internal ip addressess according to the subnetting schema defined at the beginning and are two because [the service has two replicasets defined](https://github.com/bgarcial/k8-secrets-yaml-approach/blob/master/http-echo.yaml#L22) this is why 2 pods are created:


![Hello World service on K8S](https://cldup.com/VDK3y8FNbK.png "Hello World service on K8S")

![Hello World pods on K8S](https://cldup.com/LV3h1mBXZv.png "Hello World pods on K8S")

![Hello World pods on K8S](https://cldup.com/ogc6fwO6J7.png "Hello World pods on K8S")


Having said that, if we go to https://hello-world.bgarcial.me/ we can see now we have tls encryption for that domain



![TLS encryption](https://cldup.com/1UnloaVv72.png "TLS encryption")

---




