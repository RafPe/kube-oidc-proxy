# Publishing on Artifact Hub

[Artifact Hub](https://artifacthub.io) is where most Helm users discover charts.
Listing `kube-oidc-proxy` there makes it installable and searchable beyond
GitHub, and surfaces the cosign signature we already attach to every release.

The chart is already prepared for it:

- `chart/kube-oidc-proxy/Chart.yaml` carries `artifacthub.io/*` annotations
  (category, license, links, images) that populate the listing.
- `chart/kube-oidc-proxy/artifacthub-repo.yml` is the ownership file used to
  claim the repository and become a Verified Publisher.
- Releases are signed with cosign (keyless), which Artifact Hub detects and
  displays automatically.

Registration is a one-time manual step — it needs your Artifact Hub account.

## One-time setup

1. **Sign in** at <https://artifacthub.io> (GitHub sign-in works).

2. **Add the repository** under *Control Panel → Repositories → Add*:
   - **Kind:** `Helm charts`
   - **Name:** `kube-oidc-proxy` (this becomes the URL slug)
   - **URL:** `oci://ghcr.io/rafpe/charts/kube-oidc-proxy`

3. **Copy the Repository ID** shown for the new repository and paste it into
   `chart/kube-oidc-proxy/artifacthub-repo.yml` (replacing the placeholder).
   Commit that change.

4. **Publish the ownership metadata** to the OCI registry once, so Artifact Hub
   can verify you own it (requires [`oras`](https://oras.land) and a GHCR login):

   ```bash
   echo "$GITHUB_TOKEN" | oras login ghcr.io -u <your-github-user> --password-stdin

   oras push ghcr.io/rafpe/charts/kube-oidc-proxy:artifacthub.io \
     --config /dev/null:application/vnd.cncf.artifacthub.config.v1+yaml \
     chart/kube-oidc-proxy/artifacthub-repo.yml:application/vnd.cncf.artifacthub.repository-metadata.layer.v1.yaml
   ```

Artifact Hub re-indexes the repository within a few minutes and shows the
chart, its annotations, and a "Verified Publisher" badge.

## Keeping the listing fresh

Nothing extra is needed per release. Artifact Hub polls the OCI repository and
picks up new chart versions automatically. The `artifacthub.io/*` annotations in
`Chart.yaml` travel with each packaged chart, so updating them there updates the
listing on the next release. Bump the image reference in
`artifacthub.io/images` whenever `appVersion` changes.
