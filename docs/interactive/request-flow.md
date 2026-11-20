# Request flow

<details>
<summary>Read the guide</summary>

Trace a request from the HTTPS listener to the Kubernetes API server. Each stage explains its purpose, input, and output.

## Use the explorer

1. Select a scenario.
2. Select a block to inspect its explanation.
3. Read the input, output, and behavior of the selected step.
4. Select **Copy link** to share that step.

The steps follow the proxy’s request order. Selecting a step does not run a request.

The explorer belongs to the documentation version shown in the header.
Its explanations and flow model come from the same checkout as the documentation.
The examples do not send requests to a cluster.

## Shared issuer URLs

Select **Shared issuer URL · GitHub Actions** to follow a request through authentication and Kubernetes authorization.

1. The router reads the token's `iss` and `aud` claims before verification.
2. The issuer URL selects the configured entries for that URL.
3. With several entries, the audience must select exactly one entry.
4. The selected entry verifies the token and checks its claim rules.
5. Its claim mappings produce the username and groups for Kubernetes authorization.

With one entry for a URL, the router selects that entry without using the audience.
The selected authenticator still checks the audience.
With several entries, no match or multiple matches cause `audience_unrouted`. No issuer verifies that token.
A verification failure does not try another issuer entry.
The metric `kube_oidc_proxy_oidc_issuer_tokens_total` counts each token by the selected entry and the result. The security dashboard shows it per issuer.
OIDC errors can enter TokenReview fallback when you enable passthrough.

The audience does not prove organization membership. Each entry must restrict its trust group through claim validation.
See [Multi-issuer configuration](../multi-issuer.md#several-issuers-for-one-issuer-url) for the complete YAML example.

See [Token to RBAC](./identity-and-rbac.md) for the identity model.
See [Development](../development.md) for integration tests and local cluster requirements.
See [Architecture](../architecture.md) for the component model.

</details>
