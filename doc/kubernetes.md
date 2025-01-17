# Running on Kubernetes

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
