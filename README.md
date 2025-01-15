# Octopus Server

[Octopus Server](https://github.com/metric-space-ai/octopus_server) is a central part of the [Octopus Software](https://github.com/metric-space-ai/octopus). It provides basic infrastructure and communication interfaces for all parts of the software.

## Octopus Server's high-level features

Octopus Server provides the following features:
- Chat features.
- Communication interface to OpenAI/Azure OpenAI/Anthropic/Ollama LLMs. It has support for almost 300 LLM models.
- Data privacy. It makes sure that user private or company-sensitive data will not be accidentally sent to third-party LLMs.
- It allows running Python-based Octopus AI Services that enhance system capabilities with additional, customized AI models.
- It allows users to generate, with the use of LLM, their own custom AI Service that will be running together with other Octopus AI Services.
- Administrator is allowed to upload own custom AI Services. All AI services are scanned for malicious code patterns to prevent installation of the services that would have malicious features.
- It allows running TypeScript-based Octopus WASP Applications that enhance chat experience with UI applications that can communicate with LLMs and can provide additional business logic and features.
- It allows users to generate, with the use of LLM, their own custom WASP Applications that will be running together with other Octopus WASP Applications.
- Administrator is allowed to upload own custom WASP Applications. All WASP Applications are scanned for malicious code patterns to prevent installation of the applications that would have malicious features.
- It allows running HTML/CSS/JS-based Octopus HTML Applications that enhance system capabilities.
- Administrator is allowed to upload own custom HTML Applications. All HTML Applications are scanned for malicious code patterns to prevent installation of the applications that would have malicious features.
- It provides internal, built-in system commands that can be called from the chat level like Octopus AI Services.
- Role-based privileges system that allows separation of public and private chat activities depending on user roles.
- Chat tokens audits. Allows the administrator to check LLM tokens usage.
- User files allow users to store their work in files that could be used in different chat sessions.
- Prompting agents allow users to schedule LLM prompts for automating their workflows and repetitive tasks.
- Task Assignment System allows supervisors to create tasks and tests for the users that are automatically checked for completion by AI.
- It allows to suggest which LLM and model should be used to answer particular questions during chat session.

### Running manually (for developers)

Octopus Server is built with [Rust language](https://www.rust-lang.org/). To run it manually, you need to have Rust [installed](https://www.rust-lang.org/tools/install) on your system.

Different parts of Octopus Server have different requirements:
- [PostgreSQL](https://www.postgresql.org/) is required.
- Process manager uses Linux kernel control groups for isolation purposes, so you need to run a server with root privileges if you want to run Octopus AI Services and Octopus WASP Applications on your local system.
- Python [Miniconda](https://docs.anaconda.com/miniconda/) environment is required for running Octopus AI Services.
- A Nvidia card with configured proprietary drivers is required for running some of Octopus AI Services.
- [Node](https://nodejs.org/en) environment is required for running Octopus Client and Octopus WASP Applications.
- [Ollama](https://ollama.com/) environment is required if you want to use Ollama-supported LLMs.
- [Selenium](https://www.selenium.dev/) environment is required if you want to use Octopus AI Services that depend on web scraping features.

Before running Octopus Server manually you need to make sure you have setted up these [environment variables](https://github.com/metric-space-ai/octopus_server/blob/dev/.env).

The configuration may look like the one below.

```text
DATABASE_URL=postgres://admin:admin@db/octopus_server
NEXTCLOUD_SUBDIR=octopus_retrieval/preview/
OCTOPUS_PEPPER=randompepper
OCTOPUS_PEPPER_ID=0
OCTOPUS_SERVER_PORT=8080
OCTOPUS_WS_SERVER_PORT=8081
OLLAMA_HOST=http://localhost:11434
OPENAI_API_KEY=some_api_key
SENDGRID_API_KEY=some_api_key
WASP_DATABASE_URL=postgres://admin:admin@db
WEB_DRIVER_URL=http://localhost:4444
```

You also need to have a working PostgreSQL database. Before using the software you need to migrate the database structure to the proper version. You can do this using [sqlx tool](https://github.com/launchbadge/sqlx). You can install it by running the command:

```sh
cargo install sqlx-cli
```

Using this tool, you can create and migrate a database.

```sh
sqlx database create
sqlx migrate run
Applied 20230630073639/migrate initial (34.650427ms)
Applied 20230913072315/migrate v0.2 alter chat messages (1.907569ms)
[..]
Applied 20241010085533/migrate v0.10 alter chat messages (3.282136ms)
Applied 20241125112925/migrate v0.10 create table tasks (15.058293ms)
```

When you have configured environment variables and database you may try to start Octopus Server.

```sh
cargo run
   Compiling proc-macro2 v1.0.93
   Compiling unicode-ident v1.0.14
[..]
   Compiling sqlx v0.8.3
   Compiling octopus_server v0.10.10 (/home/michal/projects/project_octopus/octopus_server)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 21s
     Running `target/debug/octopus_server`
```

You can find Octopus Server logs in octopus_server.log file.

You can build an optimized, production version of Octopus Server by running the command.

```sh
cargo build --release
   Compiling proc-macro2 v1.0.93
   Compiling unicode-ident v1.0.14
[..]
   Compiling sqlx v0.8.3
   Compiling octopus_server v0.10.10 (/home/michal/projects/project_octopus/octopus_server)
    Finished `release` profile [optimized] target(s) in 5m 00s
```

When you have a running server, you can check API documentation by visiting

```text
http://localhost:8080/swagger-ui/
```

If you have set up the [Octopus Client](https://github.com/metric-space-ai/octopus_client) application, you can now try to connect to the Octopus Server. This step should populate the parameters table in the database. If you want to make it from the API level, you can send a GET request to the endpoint

```text
http://localhost:8080/api/v1/setup
```

After setting up an Octopus Client connection to an Octopus Server, you must register an administrator account. Next, you need to log in with administrator credentials and then go to Settings->Parameters section, and set up basic parameters that will allow you to communicate with third-party LLMs.

```text
MAIN_LLM=openai
MAIN_LLM_OPENAI_API_KEY=api_key
MAIN_LLM_OPENAI_PRIMARY_MODEL=gpt-4o-mini-2024-07-18
MAIN_LLM_OPENAI_SECONDARY_MODEL=gpt-4o-2024-08-06
```

Useful development commands.

Format command makes sure that the code is properly formatted according to Rust language standards and best practices.

```sh
cargo fmt
```

The clippy command makes sure that the code follows the best practices of idiomatic Rust.

```sh
cargo clippy
   Compiling proc-macro2 v1.0.93
   Compiling unicode-ident v1.0.14
[..]
    Checking sqlx v0.8.3
    Checking octopus_server v0.10.10 (/home/michal/projects/project_octopus/octopus_server)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 22s
```

The sqlx prepare command makes sure that you have properly generated metadata files for checking SQL queries.

```sh
cargo sqlx prepare
   Compiling proc-macro2 v1.0.93
   Compiling unicode-ident v1.0.14
[..]
    Checking octopus_server v0.10.10 (/home/michal/projects/project_octopus/octopus_server)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2m 01s
query data written to .sqlx in the current directory; please check this into version control
```

Test command makes sure that changes didn't broke existing interfaces.

```sh
cargo test
   Compiling cfg-if v1.0.0
   Compiling libc v0.2.169
[..]
   Compiling sqlx v0.8.3
   Compiling octopus_server v0.10.10 (/home/michal/projects/project_octopus/octopus_server)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 3m 40s
     Running unittests src/lib.rs (target/debug/deps/octopus_server-cb0be6087dd147dd)

running 861 tests
test api::ai_functions::tests::delete_401 ... ok
test api::ai_functions::tests::delete_403_deleted_user ... ok
[..]
test api::workspaces::tests::update_404 ... ok
test api::workspaces::tests::update_403_private ... ok

test result: ok. 861 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 668.67s

     Running unittests src/main.rs (target/debug/deps/octopus_server-fb187e04b85baa1e)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests octopus_server

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

Octopus Server has a large set of functional tests that cover a large part of server API. Unfortunately, these tests are not complete enough to make any guarantee that the change didn't break server functionality. In future releases, we will try to provide more extensive set of both functional and unit tests.

If you have problem with running the Octopus Server in your environment, please have a look at this [Dockerfile](https://github.com/metric-space-ai/octopus_server/blob/dev/Dockerfile). It's used to provide production container builds. It contains all instructions needed to prepare a fully functional Octopus Server container.

### Running on Kubernetes

Managing the Kubernetes cluster is a complicated topic. We will try to describe here the steps needed to run Octopus Server using MicroK8s Kubernetes distribution shipped with Ubuntu Linux. Other Kubernetes distributions and other Linux distributions may require different steps. Please consult with a qualified administrator.

Check [MicroK8s](https://microk8s.io/) website to find out how to install this Kubernetes distribution.

After installation, you need to perform the following steps to configure basic services.

```sh
microk8s enable cert-manager
microk8s enable ingress
microk8s enable metallb
microk8s enable gpu
microk8s enable hostpath-storage
microk8s enable storage
```

If you are not a person who was trained in configuring Kubernetes clusters, please keep in mind that each of these steps could cause problems, and helping with resolving these problems goes far beyond this short documentation. Regarding problems with Kubernetes configuration please read the official Kubernetes documentation and use the help of professional DevOps.

Now, you need to configure secrets that are passed to the deployment. Please make sure you edit these values, before executing these commands.

```sh
microk8s kubectl create secret docker-registry hub-docker-com-secret --docker-username=username --docker-password=password
microk8s kubectl create secret generic octopus-pepper-secret --from-literal=octopus-pepper=pepper
microk8s kubectl create secret generic octopus-pepper-id-secret --from-literal=octopus-pepper-id=0
microk8s kubectl create secret generic octopus-server-port-secret --from-literal=octopus-server-port=8080
microk8s kubectl create secret generic octopus-ws-server-port-secret --from-literal=octopus-ws-server-port=8081
microk8s kubectl create secret generic openai-api-key-secret --from-literal=openai-api-key=api_key
microk8s kubectl create secret generic sendgrid-api-key-secret --from-literal=sendgrid-api-key=api_key
microk8s kubectl create secret generic next-public-base-url-secret --from-literal=next-public-base-url=https://api.mydomain.com/
microk8s kubectl create secret generic next-public-domain-secret --from-literal=next-public-domain=mydomain.com/
microk8s kubectl create secret generic next-public-theme-name-secret --from-literal=next-public-theme-name=default-dark
microk8s kubectl create secret generic nextcloud-password-secret --from-literal=nextcloud-password=password
microk8s kubectl create secret generic nextcloud-subdir-secret --from-literal=nextcloud-subdir=octopus_retrieval/preview/
microk8s kubectl create secret generic nextcloud-url-secret --from-literal=nextcloud-url=url
microk8s kubectl create secret generic nextcloud-username-secret --from-literal=nextcloud-username=username
microk8s kubectl create secret generic web-driver-url-secret --from-literal=web-driver-url=http://localhost:9515
```

For the PostgreSQL database, we suggest using a database shipped with Linux distribution or installing [Postgres Operator](https://github.com/CrunchyData/postgres-operator).

If you choose Postgres Operator please follow [Crunchy Postgres for Kubernetes](https://access.crunchydata.com/documentation/postgres-operator/latest/quickstart) documentation.

As the first step of configuring Octopus Software on the Kubernetes cluster, it advised to configure volumes. You can edit volume sizes to make it smaller for testing purposes. For testing purposes, you can skip creating volumes, but later, you need to edit deployment to not include volumes configuration there.

Please apply the following volumes.

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: octopus-server-huggingface-persistent-volume
  labels:
    type: local
spec:
  storageClassName: manual
  capacity:
    storage: 64Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: "/mnt/octopus-server-huggingface"
```

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: octopus-server-huggingface-persistent-volume-claim
spec:
  storageClassName: manual
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 64Gi
```

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: octopus-server-ollama-persistent-volume
  labels:
    type: local
spec:
  storageClassName: manual
  capacity:
    storage: 64Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: "/mnt/octopus-server-ollama"
```

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: octopus-server-ollama-persistent-volume-claim
spec:
  storageClassName: manual
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 64Gi
```

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: octopus-server-public-persistent-volume
  labels:
    type: local
spec:
  storageClassName: manual
  capacity:
    storage: 16Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: "/mnt/octopus-server-public"
```

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: octopus-server-public-persistent-volume-claim
spec:
  storageClassName: manual
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 16Gi
```

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: octopus-server-services-persistent-volume
  labels:
    type: local
spec:
  storageClassName: manual
  capacity:
    storage: 128Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: "/mnt/octopus-server-services"
```

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: octopus-server-services-persistent-volume-claim
spec:
  storageClassName: manual
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 128Gi
```

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: octopus-server-wasp-apps-persistent-volume
  labels:
    type: local
spec:
  storageClassName: manual
  capacity:
    storage: 32Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: "/mnt/octopus-server-wasp-apps"
```

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: octopus-server-wasp-apps-persistent-volume-claim
spec:
  storageClassName: manual
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 32Gi
```

```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: octopus-server-wasp-generator-persistent-volume
  labels:
    type: local
spec:
  storageClassName: manual
  capacity:
    storage: 16Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: "/mnt/octopus-server-wasp-generator"
```

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: octopus-server-wasp-generator-persistent-volume-claim
spec:
  storageClassName: manual
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 16Gi
```

When you have configured volumes, you can configure the service.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: octopus-server
  labels:
    group: backend
spec:
  type: ClusterIP
  selector:
    app: octopus-server
  ports:
    - name: frontend
      port: 3000
      targetPort: 3000
    - name: backend
      port: 8080
      targetPort: 8080
    - name: backend-ws
      port: 8081
      targetPort: 8081
```

After service configuration, it's time to configure deployment.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: octopus-server
  labels:
    app: octopus-server
    group: backend
spec:
  selector:
    matchLabels:
      app: octopus-server
  template:
    metadata:
      labels:
        app: octopus-server
        group: backend
    spec:
      containers:
        - name: octopus-server
          image: metricspaceai/octopus_server:v0.10.10
          env:
          - name: DATABASE_URL
            valueFrom:
              secretKeyRef:
                name: hippo-pguser-octopus-default
                key: uri
          - name: OCTOPUS_PEPPER
            valueFrom:
              secretKeyRef:
                name: octopus-pepper-secret
                key: octopus-pepper
          - name: OCTOPUS_PEPPER_ID
            valueFrom:
              secretKeyRef:
                name: octopus-pepper-id-secret
                key: octopus-pepper-id
          - name: OCTOPUS_SERVER_PORT
            valueFrom:
              secretKeyRef:
                name: octopus-server-port-secret
                key: octopus-server-port
          - name: OCTOPUS_WS_SERVER_PORT
            valueFrom:
              secretKeyRef:
                name: octopus-ws-server-port-secret
                key: octopus-ws-server-port
          - name: OPENAI_API_KEY
            valueFrom:
              secretKeyRef:
                name: openai-api-key-secret
                key: openai-api-key
          - name: SENDGRID_API_KEY
            valueFrom:
              secretKeyRef:
                name: sendgrid-api-key-secret
                key: sendgrid-api-key
          - name: NEXT_PUBLIC_BASE_URL
            valueFrom:
              secretKeyRef:
                name: next-public-base-url-secret
                key: next-public-base-url
          - name: NEXT_PUBLIC_DOMAIN
            valueFrom:
              secretKeyRef:
                name: next-public-domain-secret
                key: next-public-domain
          - name: NEXT_PUBLIC_THEME_NAME
            valueFrom:
              secretKeyRef:
                name: next-public-theme-name-secret
                key: next-public-theme-name
          - name: WASP_DATABASE_URL
            valueFrom:
              secretKeyRef:
                name: hippo-pguser-octopus-wasp-default
                key: uri
          - name: WASP_MAGE_DATABASE_URL
            valueFrom:
              secretKeyRef:
                name: hippo-pguser-octopus-wasp-mage-default
                key: uri
          - name: NEXTCLOUD_PASSWORD
            valueFrom:
              secretKeyRef:
                name: nextcloud-password-secret
                key: nextcloud-password
          - name: NEXTCLOUD_SUBDIR
            valueFrom:
              secretKeyRef:
                name: nextcloud-subdir-secret
                key: nextcloud-subdir
          - name: NEXTCLOUD_URL
            valueFrom:
              secretKeyRef:
                name: nextcloud-url-secret
                key: nextcloud-url
          - name: NEXTCLOUD_USERNAME
            valueFrom:
              secretKeyRef:
                name: nextcloud-username-secret
                key: nextcloud-username
          - name: WEB_DRIVER_URL
            valueFrom:
              secretKeyRef:
                name: web-driver-url-secret
                key: web-driver-url
          ports:
            - containerPort: 3000
              name: octopus-client
            - containerPort: 8080
              name: octopus-server
            - containerPort: 8081
              name: octopus-ws-sev
          volumeMounts:
            - name: octopus-server-huggingface-persistent-storage
              mountPath: /root/.cache/huggingface
            - name: octopus-server-ollama-persistent-storage
              mountPath: /root/.ollama
            - name: octopus-server-public-persistent-storage
              mountPath: /octopus_server/public
            - name: octopus-server-services-persistent-storage
              mountPath: /octopus_server/services
            - name: octopus-server-wasp-apps-persistent-storage
              mountPath: /octopus_server/wasp_apps
            - name: octopus-server-wasp-generator-persistent-storage
              mountPath: /octopus_server/wasp_generator
          securityContext:
            capabilities:
              add:
              - SYS_ADMIN
            allowPrivilegeEscalation: true
            privileged: true
      imagePullSecrets:
        - name: hub-docker-com-secret
      volumes:
        - name: octopus-server-huggingface-persistent-storage
          persistentVolumeClaim:
            claimName: octopus-server-huggingface-persistent-volume-claim
        - name: octopus-server-ollama-persistent-storage
          persistentVolumeClaim:
            claimName: octopus-server-ollama-persistent-volume-claim
        - name: octopus-server-public-persistent-storage
          persistentVolumeClaim:
            claimName: octopus-server-public-persistent-volume-claim
        - name: octopus-server-services-persistent-storage
          persistentVolumeClaim:
            claimName: octopus-server-services-persistent-volume-claim
        - name: octopus-server-wasp-apps-persistent-storage
          persistentVolumeClaim:
            claimName: octopus-server-wasp-apps-persistent-volume-claim
        - name: octopus-server-wasp-generator-persistent-storage
          persistentVolumeClaim:
            claimName: octopus-server-wasp-generator-persistent-volume-claim
```

Please pay attention to this part.

```yaml
          - name: DATABASE_URL
            valueFrom:
              secretKeyRef:
                name: hippo-pguser-octopus-default
                key: uri
```

You need to create 3 secrets that are based on the hippo secret from "Postgres Operator".

Secrets need to have the following names:

```text
hippo-pguser-octopus-default
hippo-pguser-octopus-wasp-default
hippo-pguser-octopus-wasp-mage-default
```

You can create a secret with a command that looks similar to this one:

```sh
microk8s kubectl apply -f - <<EOF
apiVersion: v1
data:
  dbname:
  host:
  jdbc-uri:
  password:
  port:
  uri:
  user:
  verifier:
kind: Secret
metadata:
  name: hippo-pguser-octopus-default
type: Opaque
EOF
```

Uris should point to the different databases. Value hippo-pguser-octopus-wasp-default is used for creating databases for Octopus WASP Applications.

```text
hippo-pguser-octopus-default -> postgresql://credentials@hippo-primary.postgres-operator.svc:5432/octopus_server
hippo-pguser-octopus-wasp-default -> postgresql://credentials@hippo-primary.postgres-operator.svc:5432
hippo-pguser-octopus-wasp-mage-default -> postgresql://credentials@hippo-primary.postgres-operator.svc:5432/wasp_mage
```

After successfully creating a deployment, you can create a cluster issuer. You need to have an account in [Let's Encrypt](https://letsencrypt.org/) to use their free SSL certificates.

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
  namespace: cert-manager
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: email@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: public
```

After the successful configuration of the cluster issuer, you can configure ingress.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/from-to-www-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "512m"
    nginx.ingress.kubernetes.io/proxy-connect-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    nginx.org/client-max-body-size: "512m"
  generation: 1
  name: ingress-service
  namespace: default
spec:
  tls:
    - hosts:
      - mydomain.com
      - api.mydomain.com
      secretName: mydomaincom-tls
  rules:
    - host: mydomain.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: octopus-server
                port:
                  number: 3000
    - host: api.mydomain.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: octopus-server
                port:
                  number: 8080
          - path: /ws/
            pathType: Prefix
            backend:
              service:
                name: octopus-server
                port:
                  number: 8081
```

After successful ingress configuration, you can configure the ingress service.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: ingress
  namespace: ingress
spec:
  selector:
    name: nginx-ingress-microk8s
  type: LoadBalancer
  loadBalancerIP: 1270.0.0.1
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: 80
    - name: https
      protocol: TCP
      port: 443
      targetPort: 443
```

You may need to patch the ingress to provide the external IP of your server.

```sh
microk8s kubectl patch service ingress -n ingress -p '{"spec": {"externalIPs":["1270.0.0.1"]}}'
```

Ah, what a glorious ride. It wasn't that hard to configure a working cluster using miracle Kubernetes technology. If you have any problems with configuring Kubernetes, please read [Kubernetes Documentation](https://kubernetes.io/docs/home/), ask [ChatGPT](https://chatgpt.com/) or hire qualified DevOps/MLOps.
