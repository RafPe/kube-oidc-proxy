workspace "kube-oidc-proxy" "OIDC authentication and impersonation proxy for managed Kubernetes clusters" {

    model {
        user = person "Platform user" "Runs kubectl carrying an OIDC ID token."

        idp = softwareSystem "OIDC issuer(s) / IdP" "Dex, Okta, GitHub Actions OIDC, ... issues ID tokens and publishes JWKS." {
            tags "External"
        }

        apiServer = softwareSystem "Kubernetes API server" "Managed control plane; runs TokenReview, SubjectAccessReview and RBAC for the impersonated identity." {
            tags "External"
        }

        proxy = softwareSystem "kube-oidc-proxy" "Authenticates the bearer token and impersonates the mapped user to the API server." {
            app = container "kube-oidc-proxy" "Reverse proxy that validates OIDC tokens against the union of issuers and impersonates the mapped user to the API server." "Go" {
                serving = component "Secure serving layer" "Terminates TLS and drives the handler chain." "Go, SecureServingInfo"
                authn = component "Authenticator" "Validates the bearer token against the union of N OIDC issuers." "Go, bearertoken + OIDC union"
                tokenPassthrough = component "Token passthrough" "Fallback for tokens OIDC does not accept; validated via TokenReview." "Go, TokenReview"
                impersonate = component "Impersonation handler" "Builds the impersonation config and forwards the request." "Go"
                sar = component "SubjectAccessReview client" "Authorizes inbound impersonation (kubectl --as); caps the impersonation header values per request (431 over cap) before any review is sent." "Go, SubjectAccessReview"
                audit = component "Audit backend" "Records authenticated and unauthenticated requests." "Go, k8s audit"
                probe = component "Readiness probe" "Reports Ready once each issuer's JWKS is initialized." "Go, healthcheck"
            }
        }

        # Actor -> external and system (context / container level)
        user -> idp "Logs in, obtains ID token" "OIDC"
        user -> serving "Sends kubectl requests with a bearer ID token" "HTTPS"

        # Component-level flow (higher-level relationships are implied from these)
        serving -> authn "1. Authenticate the token"
        authn -> idp "Fetch and cache JWKS" "HTTPS"
        authn -> tokenPassthrough "On OIDC failure, fall back"
        tokenPassthrough -> apiServer "TokenReview, then forward caller token unchanged" "HTTPS"
        authn -> impersonate "2. On success, resolve identity"
        impersonate -> sar "Authorize inbound --as"
        sar -> apiServer "SubjectAccessReview" "HTTPS"
        impersonate -> apiServer "3. Forward with Impersonate- headers" "HTTPS"
        impersonate -> audit "4. Emit audit events"
        probe -> authn "Probe JWKS init with a fake JWT"
    }

    views {
        systemContext proxy "SystemContext" "Who talks to the proxy and what it depends on." {
            include *
            autoLayout
        }

        container proxy "Containers" "The proxy as a single deployable, and the systems it integrates with." {
            include *
            autoLayout
        }

        component app "Components" "The request-handling components inside the proxy." {
            include *
            autoLayout
        }

        styles {
            element "Person" {
                shape Person
                background #08427b
                color #ffffff
            }
            element "Software System" {
                background #1168bd
                color #ffffff
            }
            element "Container" {
                background #438dd5
                color #ffffff
            }
            element "Component" {
                background #85bbf0
                color #000000
            }
            element "External" {
                background #999999
                color #ffffff
            }
        }
    }
}
