# Istio Deployment Example

## Overview

This example shows how to deploy the Envoy AVP (Amazon Verified Permissions) Authorizer with Istio service mesh. The authorizer acts as an external authorization service that validates JWT tokens and makes authorization decisions using AWS Verified Permissions.

## Prerequisites

- Kubernetes cluster with Istio installed
- AWS IAM Role or User configured for Verified Permissions access
- Prefer providing credentials via EC2 Instance Profile, ECS Task Role, EKS Pod Identity, IRSA etc.

## Create the authorization service

This sets up the authorization service including a resource mapping file. 

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: avp-system
  labels:
    istio-injection: enabled
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: avp-resource-mapping
  namespace: avp-system
data:
  mapping.json: |
    {
      "patterns": [
        {
          "pattern": "app",
          "resource_type": "TinyTodo::Application",
          "resource_id": "app",
          "parents": [],
          "parameter_groups": {}
        },
        {
          "pattern": "app/shared",
          "resource_type": "TinyTodo::Application",
          "resource_id": "app",
          "parents": [],
          "parameter_groups": {}
        },
        {
          "pattern": "app/lists",
          "resource_type": "TinyTodo::Application",
          "resource_id": "app",
          "parents": [],
          "parameter_groups": {}
        },
        {
          "pattern": "lists",
          "resource_type": "TinyTodo::List",
          "resource_id": null,
          "parents": [],
          "parameter_groups": {}
        },
        {
          "pattern": "lists/{id}",
          "resource_type": "TinyTodo::List",
          "resource_id": "${id}",
          "parents": [],
          "parameter_groups": {}
        },
        {
          "pattern": "lists/{listId}/tasks",
          "resource_type": "TinyTodo::Task",
          "resource_id": null,
          "parents": [
            {
              "parent_type": "TinyTodo::List",
              "parent_id": "${listId}"
            }
          ],
          "parameter_groups": {}
        },
        {
          "pattern": "lists/{listId}/tasks/{id}",
          "resource_type": "TinyTodo::Task",
          "resource_id": "${id}",
          "parents": [
            {
              "parent_type": "TinyTodo::List",
              "parent_id": "${listId}"
            }
          ],
          "parameter_groups": {}
        },
        {
          "pattern": "app/{appId}/lists/{listId}/tasks/{id}",
          "resource_type": "TinyTodo::Task",
          "resource_id": "${id}",
          "parents": [
            {
              "parent_type": "TinyTodo::List",
              "parent_id": "${listId}"
            },
            {
              "parent_type": "TinyTodo::Application",
              "parent_id": "${appId}"
            }
          ],
          "parameter_groups": {}
        },
        {
          "pattern": "app/{appId}/lists/{listId}/tasks/{id}/versions/{versionId}",
          "resource_type": "TinyTodo::Task",
          "resource_id": "${id}",
          "parents": [
            {
              "parent_type": "TinyTodo::List",
              "parent_id": "${listId}"
            },
            {
              "parent_type": "TinyTodo::Application",
              "parent_id": "${appId}"
            }
          ],
          "parameter_groups": {
            "version": "versionId"
          }
        }
      ],
      "action_mappings": [
        {
          "path_pattern": "app",
          "mappings": {
            "GET": "TinyTodo::Action::ListLists"
          }
        },
        {
          "path_pattern": "app/shared",
          "mappings": {
            "GET": "TinyTodo::Action::ListSharedLists"
          }
        },
        {
          "path_pattern": "app/lists",
          "mappings": {
            "GET": "TinyTodo::Action::ListLists",
            "POST": "TinyTodo::Action::CreateList"
          }
        },
        {
          "path_pattern": "lists",
          "mappings": {
            "GET": "TinyTodo::Action::ListLists",
            "POST": "TinyTodo::Action::CreateList"
          }
        },
        {
          "path_pattern": "lists/{id}",
          "mappings": {
            "GET": "TinyTodo::Action::GetList",
            "PUT": "TinyTodo::Action::UpdateList",
            "DELETE": "TinyTodo::Action::DeleteList"
          }
        },
        {
          "path_pattern": "lists/{listId}/tasks",
          "mappings": {
            "GET": "TinyTodo::Action::ListTasks",
            "POST": "TinyTodo::Action::CreateTask"
          }
        },
        {
          "path_pattern": "lists/{listId}/tasks/{id}",
          "mappings": {
            "GET": "TinyTodo::Action::GetTask",
            "PUT": "TinyTodo::Action::UpdateTask",
            "DELETE": "TinyTodo::Action::DeleteTask"
          }
        },
        {
          "path_pattern": "app/{appId}/lists/{listId}/tasks/{id}",
          "mappings": {
            "GET": "TinyTodo::Action::GetTask",
            "PUT": "TinyTodo::Action::UpdateTask",
            "DELETE": "TinyTodo::Action::DeleteTask"
          }
        },
        {
          "path_pattern": "app/{appId}/lists/{listId}/tasks/{id}/versions/{versionId}",
          "mappings": {
            "GET": "TinyTodo::Action::GetTask",
            "PUT": "TinyTodo::Action::UpdateTask",
            "DELETE": "TinyTodo::Action::DeleteTask"
          }
        }
      ]
    }
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: avp-authorizer
  namespace: avp-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: avp-authorizer
  namespace: avp-system
  labels:
    app: avp-authorizer
    version: v1
spec:
  replicas: 2
  selector:
    matchLabels:
      app: avp-authorizer
      version: v1
  template:
    metadata:
      labels:
        app: avp-authorizer
        version: v1
    spec:
      serviceAccountName: avp-authorizer
      containers:
      - name: avp-authorizer
        image: ghcr.io/robmdunn/envoy-avp-authorizer:latest
        ports:
        - containerPort: 50051
          name: grpc
        - containerPort: 9000
          name: metrics
        env:
        - name: AVP_REGION
          value: "us-east-1"
        - name: AVP_POLICY_STORE_ID
          value: "<Policy Store ID>"  
        - name: AVP_LISTEN_ADDRESS
          value: "0.0.0.0:50051"
        - name: AVP_JWT_ISSUER
          value: "<your issuer>"
        - name: AVP_JWT_AUDIENCE
          value: "<your token audience>"
        - name: AVP_JWKS_URL
          value: "<your jwks>"
        - name: AVP_JWKS_CACHE_DURATION
          value: "3600"
        - name: AVP_POLICY_CACHE_TTL
          value: "60"
        - name: AVP_POLICY_CACHE_SIZE
          value: "10000"
        - name: AVP_RESOURCE_MAPPING_PATH
          value: "/etc/avp/mapping.json"
        - name: AVP_API_PREFIX_PATTERN
          value: "/api/v*/"
        - name: AVP_LOG_LEVEL
          value: "info"
        - name: AVP_ENABLE_METRICS
          value: "true"
        volumeMounts:
        - name: resource-mapping
          mountPath: /etc/avp
          readOnly: true
        livenessProbe:
          grpc:
            port: 50051
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          grpc:
            port: 50051
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: resource-mapping
        configMap:
          name: avp-resource-mapping
---
apiVersion: v1
kind: Service
metadata:
  name: avp-authorizer
  namespace: avp-system
  labels:
    app: avp-authorizer
spec:
  selector:
    app: avp-authorizer
  ports:
  - name: grpc
    port: 50051
    targetPort: 50051
    protocol: TCP
  - name: metrics
    port: 9000
    targetPort: 9000
    protocol: TCP
```

Once the authorization service is up and running, update the Istio ConfigMap to add the authorization service as an external authorizer: 

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: istio
  namespace: istio-system
data:
  mesh: |-
    ...
    extensionProviders:
    - name: avp-authorizer
      envoyExtAuthzGrpc:
        service: avp-authorizer.avp-system.svc.cluster.local
        port: 50051
    ...
```

Once the external authorizer is configured, you can create a demo application to test authorization decisions:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: authz-test
  labels:
    istio-injection: enabled
    name: authz-test
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-app
  namespace: authz-test
  labels:
    app: nginx-app
    version: v1
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx-app
      version: v1
  template:
    metadata:
      labels:
        app: nginx-app
        version: v1
    spec:
      containers:
      - name: nginx
        image: nginx:1.25-alpine
        ports:
        - containerPort: 80
          name: http
        volumeMounts:
        - name: nginx-config
          mountPath: /etc/nginx/conf.d
        - name: html-content
          mountPath: /usr/share/nginx/html
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "100m"
      volumes:
      - name: nginx-config
        configMap:
          name: nginx-config
      - name: html-content
        configMap:
          name: html-content
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-app
  namespace: authz-test
  labels:
    app: nginx-app
spec:
  selector:
    app: nginx-app
  ports:
  - name: http
    port: 80
    targetPort: 80
    protocol: TCP
  type: ClusterIP
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-config
  namespace: authz-test
data:
  default.conf: |
    server {
        listen 80;
        server_name localhost;
        
        # Add headers to show what's happening
        add_header X-Server-Name $hostname always;
        add_header X-Request-ID $request_id always;
        
        # Use default log format
        access_log /var/log/nginx/access.log;
        
        location / {
            root /usr/share/nginx/html;
            index index.html;
        }
        
        # API endpoints that will be protected
        location /api/v1/app {
            alias /usr/share/nginx/html/app.json;
            add_header Content-Type application/json;
            add_header X-Path $uri always;
            add_header X-Method $request_method always;
        }
        
        location /api/v1/lists {
            alias /usr/share/nginx/html/lists.json;
            add_header Content-Type application/json;
            add_header X-Path $uri always;
            add_header X-Method $request_method always;
        }
        
        # Generic API path for other endpoints
        location /api/ {
            return 200 '{"message": "API endpoint", "path": "$uri", "method": "$request_method"}';
            add_header Content-Type application/json;
            add_header X-Path $uri always;
            add_header X-Method $request_method always;
        }
        
        # Health check endpoint (unprotected)
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: html-content
  namespace: authz-test
data:
  index.html: |
    <!DOCTYPE html>
    <html>
    <head>
        <title>AVP Authorization Test</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .endpoint { background: #f4f4f4; padding: 20px; margin: 10px 0; border-radius: 5px; }
            .protected { border-left: 4px solid #ff6b6b; }
            .unprotected { border-left: 4px solid #51cf66; }
        </style>
    </head>
    <body>
        <h1>AVP Authorization Test Server</h1>
        <p>This server is used to test external authorization with Istio and AVP.</p>
        
        <h2>Available Endpoints:</h2>
        
        <div class="endpoint unprotected">
            <h3>GET / (Unprotected)</h3>
            <p>This page - should always be accessible</p>
        </div>
        
        <div class="endpoint unprotected">
            <h3>GET /health (Unprotected)</h3>
            <p>Health check endpoint</p>
        </div>
        
        <div class="endpoint protected">
            <h3>GET /api/v1/app (Protected)</h3>
            <p>Protected endpoint - requires valid JWT</p>
        </div>
        
        <div class="endpoint protected">
            <h3>GET /api/v1/lists (Protected)</h3>
            <p>Protected endpoint - requires valid JWT</p>
        </div>
        
        <div class="endpoint protected">
            <h3>GET /api/v1/lists/123 (Protected)</h3>
            <p>Protected endpoint with resource ID - requires valid JWT</p>
        </div>
        
        <div class="endpoint protected">
            <h3>POST /api/v1/lists (Protected)</h3>
            <p>Protected endpoint for creating resources - requires valid JWT</p>
        </div>
    </body>
    </html>
  app.json: |
    {
      "message": "App endpoint accessed successfully",
      "resource": "TinyTodo::Application",
      "resource_id": "app",
      "timestamp": "2025-01-01T00:00:00Z"
    }
  lists.json: |
    {
      "message": "Lists endpoint accessed successfully",
      "resource": "TinyTodo::List",
      "lists": [
        {"id": "list1", "name": "Shopping"},
        {"id": "list2", "name": "Work Tasks"}
      ],
      "timestamp": "2025-01-01T00:00:00Z"
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: curl-utility
  namespace: authz-test
  labels:
    app: curl-utility
    version: v1
spec:
  replicas: 1
  selector:
    matchLabels:
      app: curl-utility
      version: v1
  template:
    metadata:
      labels:
        app: curl-utility
        version: v1
    spec:
      containers:
      - name: curl
        image: curlimages/curl:8.5.0
        command: ["/bin/sh"]
        args: ["-c", "while true; do sleep 3600; done"]
        env:
        - name: NGINX_SERVICE
          value: "nginx-app.authz-test.svc.cluster.local"
        resources:
          requests:
            memory: "32Mi"
            cpu: "25m"
          limits:
            memory: "64Mi"
            cpu: "50m"
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: avp-external-authz
  namespace: authz-test
spec:
  selector:
    matchLabels:
      app: nginx-app
  action: CUSTOM
  provider:
    name: avp-authorizer
  rules:
  - to:
    - operation:
        paths: ["/api/*"]
        methods: ["GET", "POST", "PUT", "DELETE"]
```

You can exec into the curl container to test the API:

```bash
export JWT_TOKEN=<your token>
~ $ curl http://nginx-app.authz-test.svc.cluster.local./api/v1/app  -H "Authorization: Bearer $JWT_TOKEN"
{
  "message": "App endpoint accessed successfully",
  "resource": "TinyTodo::Application",
  "resource_id": "app",
  "timestamp": "2025-01-01T00:00:00Z"
}

~ $ curl http://nginx-app.authz-test.svc.cluster.local./api/v1/lists  -H "Authorization: Bearer $JWT_TOKEN"
```

You should see requests approved or denied in the envoy-avp-authorizer container logs:
```
2025-05-31T03:21:26.112852Z  INFO envoy_avp_authorizer::authorization_service: AUTHORIZATION ALLOWED: principal=User::exampleuser, action=TinyTodo::Action::ListLists, resource=TinyTodo::Application::app, path=/api/v1/app, cached=true
2025-05-31T03:21:55.240771Z  WARN envoy_avp_authorizer::authorization_service: AUTHORIZATION DENIED: principal=User::exampleuser, action=TinyTodo::Action::ListLists, resource=TinyTodo::List::TinyTodo::List, path=/api/v1/lists, cached=false
```