# Install the control plane

The supported install is the Helm chart at `charts/ipso` and the Compose bundle at `deploy/bundle`. The file `compose.yaml` in the repository root is the laptop stack, with Dex and a test user, and it is not this install. The decisions are [ADR-0140](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0140-self-hosted-chart-and-bundle.md).

You need Helm 4 and Kubernetes 1.29 or newer for the chart, or Docker Compose v2 for the bundle. The api process discovers an https identity provider at start. The chart and the bundle do not run one, and they do not create a person unless you ask them to.

## Chart values

| Value | Default | What it does |
| --- | --- | --- |
| `image.repository` | `ghcr.io/ipsofacto-io/ipso-server` | Server image. The reference is `repository@digest`. A tag is refused. |
| `image.digest` | empty | Required. No server image is published yet, so a cluster install loads one you built and sets this to its digest. |
| `existingSecret` | empty | Required. Name of a Secret you create. The chart does not create a Secret and does not read passwords from values. |
| `tenantID` | empty | Required. The one tenant this release serves. |
| `oidc.issuer` | empty | Required. https issuer. |
| `oidc.audience` | empty | Required. Client id the api accepts as the token audience. |
| `oidc.caSecretKey` | empty | Optional key in `existingSecret` whose PEM replaces the api trust store. Leave it empty for a public issuer. Do not set it on the worker: premise probes need the public roots. |
| `oidc.namespace` | empty | Namespace of an in-cluster issuer that is not in the release namespace. Empty leaves that path closed. A public issuer does not need it. |
| `oidc.port` | `443` | Port in the issuer URL. Used only when `oidc.namespace` is set. |
| `bootstrap.enabled` | `false` | When true, a Job creates the tenant and its first person. |
| `bootstrap.kekSecret` | empty | Secret that holds key `tenant-kek`, mounted only on that Job. |
| `postgresql.enabled` | `true` | In-cluster PostgreSQL 18. Set false to use a database you prepared. |
| `postgresql.cidr` | empty | When PostgreSQL is external, egress to TCP 5432. Empty allows any address except link-local. |
| `front.tls.enabled` | `false` | Adds `Strict-Transport-Security` on the front. The chart does not terminate TLS. |
| `api.replicas` | `1` | Api pods. |
| `worker.replicas` | `1` | Worker pods. Two workers for the same tenant are supported. |
| `networkPolicy.enabled` | `true` | Default-deny policies for the chart's pods. |

The front Service is ClusterIP. Ingress is not installed. Nothing in the default values is a password or a client secret.

## Secret

Create the Secret before `helm install`. With in-cluster PostgreSQL and a release named `ipso`, the database host is `ipso-postgresql` (the Service `{{ fullname }}-postgresql`).

```sh
kubectl create secret generic ipso -n ipso \
  --from-literal=postgres-password='replace-me' \
  --from-literal=migrate-password='replace-me' \
  --from-literal=app-password='replace-me' \
  --from-literal=database-url='postgres://ipso_app:replace-me@ipso-postgresql:5432/ipso?sslmode=disable' \
  --from-literal=migrate-database-url='postgres://ipso_migrate:replace-me@ipso-postgresql:5432/ipso?sslmode=disable'
```

`migrate-database-url` is mounted only on the migrate Job. `database-url` is mounted on the api, the worker, and the bootstrap Job. When PostgreSQL is external, omit the three password keys and point the URLs at that host. The database must already have the roles, the empty database, and `ipso.current_tenant()` from `charts/ipso/files/postgres-init.sh`.

A private issuer CA is an extra key, named by `oidc.caSecretKey`:

```sh
kubectl create secret generic ipso -n ipso --from-file=oidc-ca.pem=ca.pem --dry-run=client -o yaml | kubectl apply -f -
```

Apply that together with the other keys. `SSL_CERT_FILE` replaces Go's pool, so the file has to contain every root the api should trust.

The bootstrap key is a different Secret:

```sh
kubectl create secret generic ipso-kek -n ipso --from-literal=tenant-kek="$(openssl rand -base64 32)"
```

Turn `bootstrap.enabled` off after the Job succeeds, upgrade, and delete `ipso-kek`. A later upgrade does not need the key.

### Sealed Secrets

The chart does not install a controller. You encrypt the Secret above and apply the result yourself. `existingSecret` is the name of the Secret the controller writes.

```yaml
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: ipso
  namespace: ipso
spec:
  encryptedData:
    database-url: ""
    migrate-database-url: ""
    postgres-password: ""
    migrate-password: ""
    app-password: ""
  template:
    metadata:
      name: ipso
      namespace: ipso
```

`kubeseal` fills `encryptedData`. Leave the real values out of the chart and out of git.

### External Secrets

The chart does not install External Secrets either. An `ExternalSecret` you apply can write the same Secret name:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: ipso
  namespace: ipso
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: your-store
    kind: SecretStore
  target:
    name: ipso
  data:
    - secretKey: database-url
      remoteRef:
        key: ipso/database-url
    - secretKey: migrate-database-url
      remoteRef:
        key: ipso/migrate-database-url
```

Add the password keys the same way when PostgreSQL runs in the cluster.

## Install

```sh
helm upgrade --install ipso charts/ipso --namespace ipso --create-namespace \
  --set-string image.digest=sha256:the-digest-you-loaded \
  --set-string existingSecret=ipso \
  --set-string tenantID=00000000-0000-4000-8000-000000000001 \
  --set-string oidc.issuer=https://idp.example.com/ \
  --set-string oidc.audience=ipso-api
kubectl --namespace ipso rollout status statefulset/ipso-postgresql --timeout=10m
kubectl --namespace ipso rollout status deploy/ipso-api --timeout=10m
kubectl --namespace ipso rollout status deploy/ipso-worker --timeout=10m
kubectl --namespace ipso rollout status deploy/ipso-front --timeout=10m
```

`--set-string` keeps the digest and the issuer as strings. Those values are stored in the Helm release Secret. A database URL or a key belongs in `existingSecret`. Helm returns after the migrate Job and, when you enabled it, the bootstrap Job. On a first install those Jobs run after the workloads are created, and the api and the worker restart until the schema and the tenant exist. That is what the startup probes are for. Leave off `--wait`. In Helm 4 that flag selects the watcher strategy, which requires the api to be ready before the post-install Jobs run. Wait for the rollouts after Helm returns. Skip the StatefulSet when `postgresql.enabled` is false.

To create the first person on that install, also set `bootstrap.enabled=true`, `bootstrap.kekSecret`, `bootstrap.tenantName`, `bootstrap.person`, `bootstrap.personName`, and `bootstrap.subject`. The issuer and the subject are the ones your identity provider puts on that person. The Job is safe to run again with the same arguments and refuses different ones.

`GET /healthz` on the front returns 204 after the api has passed its start gates: the application role, a tenant row, and the issuer's metadata. It does not check a token. Every other route still requires the issuer.

## Network

Each chart pod is default-deny when `networkPolicy.enabled` is true. DNS is allowed. The api may reach pods in the release namespace, and TCP 443 on public addresses. Set `oidc.namespace` and `oidc.port` when the issuer is an in-cluster Service in another namespace: that opens TCP to pods in that namespace on that port, and it does not open the private ranges. The worker may reach PostgreSQL, and TCP 80 and 443 on public addresses, which is the premise probe. The migrate Job, the bootstrap Job, and the worker do not get the api's open namespace egress. Public allows exclude `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `169.254.0.0/16`.

kindnet does not enforce NetworkPolicy, and a default k3s install does not either. The manifest is still applied. A cluster enforces it when its CNI does.

The chart does not deploy `ipso-server webhooks`. That process is the one that should be allowed to reach a Git provider, and this chart does not grant the api or the worker a reason to hold GitHub App credentials.

## Reindex

River's reindexer is off, because `ipso_app` does not own `river.river_job` and does not have `MAINTAIN`. Connect as `ipso_migrate`, or as another role that owns the table, and run:

```sql
REINDEX TABLE river.river_job;
```

Do not run it as `ipso_app`. A worker killed while a sweep is running leaves that job `running`. River's rescuer moves it after about an hour. That skips one tick. The sweep reads what is due, so the notice is delayed and not lost. The worker's connection has to be a session connection. A transaction-mode pooler in front of PostgreSQL does not work.

## Upgrade

`helm upgrade` rolls the api and the worker with `maxUnavailable: 0` and runs the migrate Job again. Migrations are forward-only. Wait for the rollouts the same way as the install, and leave off `--wait`.

No chart version has been published, so there is no product N-2 yet. The support promise still starts at GA. Until then, `ci / chart` builds an image with the two highest goose files removed, installs it on kind, and upgrades to the image that has them. It checks `/healthz` and `max(version_id)` in `goose_db_version`. The job's limit is 30 minutes, including that install reaching `/healthz`.

Publishing `oci://ghcr.io/ipsofacto-io/charts/ipso` and signing the image with keyless cosign are the release workflow, not this chart.

## HSTS

Set `front.tls.enabled` to `true` when a proxy in front of the Service terminates TLS. The header is `Strict-Transport-Security: max-age=31536000`. The chart does not create a certificate or an Ingress.

## Compose bundle

```sh
cp deploy/bundle/.env.example deploy/bundle/.env
# Fill deploy/bundle/.env. Every empty value refuses to start.
docker compose -f deploy/bundle/compose.yaml --env-file deploy/bundle/.env up --build
docker compose -f deploy/bundle/compose.yaml --env-file deploy/bundle/.env --profile bootstrap run --rm bootstrap
```

The front listens on port 8080. There is no default user. The api restarts until the issuer answers and the bootstrap command has created the tenant. PostgreSQL is not published on the host.

For browser sign-in, set `IPSO_PUBLIC_URL` and `IPSO_LOGIN_PROVIDERS` on the api the way [docs/login.md](login.md) describes. A private CA is a file you mount on the api only, with `SSL_CERT_FILE` pointing at it. That variable replaces the public roots for that process, so the worker does not get it.

`docker compose -f deploy/bundle/compose.yaml down --volumes` removes the database.

## Air-gapped bundle

`ci / airgap` builds `ghcr.io/ipsofacto-io/ipso-server` from this repository and packs it with the PostgreSQL and nginx digests the chart already pins, the packaged chart, and `deploy/bundle` ([ADR-0142](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0142-air-gapped-oci-bundle.md), [ADR-0143](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0143-air-gapped-bundle-manifest-signature.md)). The tar also has a CycloneDX SBOM for each image, a sigstore bundle for each signature and each SBOM attestation, a signed `manifest.sha256` (`signatures/manifest.sigstore.json`) covering every non-bootstrap file in the tar (every file except `manifest.sha256`, `signatures/manifest.sigstore.json`, and `trusted-root.json`), the public Sigstore trusted root captured when the tar was built, and `airgap-values.yaml`, which sets only `image.digest`. Dex and the kind node are not in the tar. The job signs with keyless cosign 3.1.4, does not push to GHCR, and uploads the `ipso-airgap` artifact only on `push` to `main`. Publishing `oci://ghcr.io/ipsofacto-io/charts/ipso` stays the release workflow.

The image signature covers the manifest digest, and `signatures/manifest.sigstore.json` covers `manifest.sha256` (`airgap-values.yaml`, `deploy/bundle/compose.yaml`, `deploy/bundle/.env.example`, `deploy/compose/postgres-init.sh`, `deploy/compose/nginx.conf`, the SBOMs, `chart/ipso-*.tgz`, `signatures/chart.sigstore.json`, and the image layout blobs). The certificate is the `ci` workflow on `refs/heads/main` in `ipsofacto-io/ipso-server`, issued by `https://token.actions.githubusercontent.com` (same-repository pull-request CI self-tests sign against `refs/pull/<n>/(merge|head)` and upload no artifact). In production, fetch and SHA-256-pin `trusted-root-oob.json` out of band on an online workstation with `cosign trusted-root create --with-default-services --out trusted-root-oob.json` and keep it outside the extraction directory, inspect `tar -tf ipso-airgap.tar` for unexpected paths or non-regular entries, extract only `trusted-root.json`, `manifest.sha256`, and `signatures/manifest.sigstore.json` first (at most 4 MiB each), verify `manifest.sha256` offline inside `unshare --net` against `trusted-root-oob.json`, confirm `cmp -s trusted-root.json trusted-root-oob.json`, and then extract and verify the remaining regular files against `manifest.sha256` (or run `AIRGAP_ARCHIVE=$PWD/ipso-airgap.tar AIRGAP_TRUSTED_ROOT=$PWD/trusted-root-oob.json bash deploy/airgap/ci.sh verify`) before checking the image layouts and chart archive. PostgreSQL and nginx are the pinned index digests, signed by that workflow, and `images/postgres` and `images/nginx` are sparse OCI layouts carrying each signed index, its linux/amd64 manifest, config, and layers, and the referrer bundles. Also check after verification that `airgap-values.yaml` and `deploy/bundle/compose.yaml` name the server digest `cosign verify` reported for `images/ipso-server`.

```sh
# 1. Extract only the three bootstrap files into a fresh directory; keep trusted-root-oob.json outside it.
mkdir airgap-extract && cd airgap-extract
tar --no-same-owner --no-same-permissions -xf ../ipso-airgap.tar ./trusted-root.json ./manifest.sha256 ./signatures/manifest.sigstore.json
unshare --user --map-root-user --net -- cosign verify-blob \
  --bundle signatures/manifest.sigstore.json \
  --trusted-root ../trusted-root-oob.json \
  --certificate-identity-regexp '^https://github\.com/ipsofacto-io/ipso-server/\.github/workflows/ci\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  manifest.sha256
cmp -s trusted-root.json ../trusted-root-oob.json

# 2. Prefer `AIRGAP_ARCHIVE=$PWD/../ipso-airgap.tar AIRGAP_TRUSTED_ROOT=$PWD/../trusted-root-oob.json bash deploy/airgap/ci.sh verify` for streaming extraction; if extracting manually after inspecting `tar -tvf`, extract only the paths listed in the verified manifest and check every digest.
sed 's/^[0-9a-f]\{64\}  /\.\//' manifest.sha256 | tar --no-same-owner --no-same-permissions --no-recursion -xf ../ipso-airgap.tar -T -
sha256sum -c manifest.sha256

# 3. Verify image layouts, CycloneDX attestations, and the chart archive offline.
unshare --user --map-root-user --net -- cosign verify --local-image images/ipso-server \
  --trusted-root ../trusted-root-oob.json \
  --certificate-identity-regexp '^https://github\.com/ipsofacto-io/ipso-server/\.github/workflows/ci\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
unshare --user --map-root-user --net -- cosign verify-attestation --local-image images/ipso-server --type cyclonedx \
  --trusted-root ../trusted-root-oob.json \
  --certificate-identity-regexp '^https://github\.com/ipsofacto-io/ipso-server/\.github/workflows/ci\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
unshare --user --map-root-user --net -- cosign verify-blob --bundle signatures/chart.sigstore.json \
  --trusted-root ../trusted-root-oob.json \
  --certificate-identity-regexp '^https://github\.com/ipsofacto-io/ipso-server/\.github/workflows/ci\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  chart/ipso-*.tgz
```

Repeat `verify` and `verify-attestation` with `images/postgres` and `images/nginx`. Load `images/ipso-server`, `images/postgres`, and `images/nginx` into the cluster, and tag `repository@digest` for the server digest in `airgap-values.yaml` and for the PostgreSQL and nginx index digests in the chart. When importing `images/ipso-server` with `ctr`, pass `--base-name ghcr.io/ipsofacto-io/ipso-server --digests`; when importing `images/postgres` and `images/nginx`, replace `index.json` in the import stream with `blobs/sha256/<index-digest>` and pass `--index-name <repository>@<index-digest> --platform linux/amd64` (as `deploy/airgap/ci.sh` does) so containerd stores the exact signed index digest. With registry egress closed:

```sh
helm upgrade --install ipso chart/ipso-*.tgz --namespace ipso \
  -f airgap-values.yaml -f your-values.yaml
```

`your-values.yaml` names the Secret, the tenant, and the issuer, as in the chart section above. The Compose file in the tar has no build. Load those same three runnable images into Docker and start it with `--env-file deploy/bundle/.env`.
