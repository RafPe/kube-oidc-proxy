# Dex issuer template. run.sh renders this once per issuer with `sed`,
# substituting the __PLACEHOLDER__ tokens below. The serving TLS certificate
# is supplied separately as the Secret `__NAME__-tls` (created by run.sh with
# `kubectl create secret tls`), whose SANs cover the in-cluster Service DNS.
#
# The `issuer:` value MUST equal the in-cluster Service DNS so that Dex's
# discovery document advertises exactly the URL kube-oidc-proxy dials.
apiVersion: v1
kind: ConfigMap
metadata:
  name: __NAME__-config
  namespace: dex
data:
  config.yaml: |
    issuer: __ISSUER__
    storage:
      type: memory
    web:
      https: 0.0.0.0:5556
      tlsCert: /etc/dex/tls/tls.crt
      tlsKey: /etc/dex/tls/tls.key
    oauth2:
      # Enable the resource-owner password grant so a token can be minted with
      # a single curl, no browser redirect required.
      passwordConnector: local
    enablePasswordDB: true
    staticClients:
      - id: demo
        name: demo
        secret: __CLIENT_SECRET__
        redirectURIs:
          - http://localhost:8000/callback
    staticPasswords:
      - email: __USER_EMAIL__
        # bcrypt hash of the password "password".
        hash: "__HASH__"
        username: __USER_NAME__
        userID: __USER_ID__
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: __NAME__
  namespace: dex
  labels:
    app: __NAME__
spec:
  replicas: 1
  selector:
    matchLabels:
      app: __NAME__
  template:
    metadata:
      labels:
        app: __NAME__
    spec:
      containers:
        - name: dex
          image: __IMAGE__
          args:
            - dex
            - serve
            - /etc/dex/cfg/config.yaml
          ports:
            - name: https
              containerPort: 5556
          readinessProbe:
            httpGet:
              scheme: HTTPS
              path: /dex/.well-known/openid-configuration
              port: 5556
            initialDelaySeconds: 2
            periodSeconds: 3
          volumeMounts:
            - name: config
              mountPath: /etc/dex/cfg
              readOnly: true
            - name: tls
              mountPath: /etc/dex/tls
              readOnly: true
      volumes:
        - name: config
          configMap:
            name: __NAME__-config
        - name: tls
          secret:
            secretName: __NAME__-tls
---
apiVersion: v1
kind: Service
metadata:
  name: __NAME__
  namespace: dex
  labels:
    app: __NAME__
spec:
  selector:
    app: __NAME__
  ports:
    - name: https
      port: 5556
      targetPort: 5556
