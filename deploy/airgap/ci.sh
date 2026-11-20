#!/usr/bin/env bash
# Pack the ADR-0140 install into one tar, sign it, and install that tar on kind
# with the node's registry egress cut (ADR-0142).
# Keyless signing needs the Actions OIDC token. There is no second key.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

cluster=ipso-airgap
registry_name=ipso-airgap-registry
# zot v2.1.23 linux/amd64. cosign 3.1.4 stores the bundle as an OCI referrer.
# The distribution registry image through 3.1.2 does not implement that API, so cosign save would not see the bundles.
registry_image=ghcr.io/project-zot/zot@sha256:b68f727fe35c1eb45b2ae91519dfb0e33192d69b5104882c3e7809b7146c4a02
server_repo=ghcr.io/ipsofacto-io/ipso-server
kind_node=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
identity='^https://github\.com/ipsofacto-io/ipso-server/\.github/workflows/ci\.yml@'
issuer=https://token.actions.githubusercontent.com

out=${RUNNER_TEMP:-/tmp}/ipso-airgap
stage=$out/stage
extract=$out/extract
archive=$out/ipso-airgap.tar
kind_pid=

require_tools() {
  local cmd
  for cmd in docker helm kind kubectl cosign syft crane openssl python3 curl; do
    command -v "$cmd" >/dev/null
  done
  if [[ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" || -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]]; then
    echo "keyless signing needs the Actions OIDC token" >&2
    exit 1
  fi
}

pinned_digest() {
  local image=$1
  sed -n "s/.*image: ${image}:.*@//p" compose.yaml | head -1
}

require_pins() {
  pg=$(pinned_digest 'postgres')
  ngx=$(pinned_digest 'nginxinc[^@]*')
  if [[ ! "$pg" =~ ^sha256:[0-9a-f]{64}$ || ! "$ngx" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "could not read the pinned postgres and nginx digests" >&2
    exit 1
  fi
  grep -q "$pg" charts/ipso/values.yaml
  grep -q "$pg" deploy/bundle/compose.yaml
  grep -q "$ngx" charts/ipso/values.yaml
  grep -q "$ngx" deploy/bundle/compose.yaml
  cmp charts/ipso/files/postgres-init.sh deploy/compose/postgres-init.sh
}

dump() {
  kubectl -n ipso get pods -o wide || true
  kubectl -n ipso get events --sort-by=.lastTimestamp || true
  kubectl -n ipso describe pods || true
  kubectl -n ipso logs -l app.kubernetes.io/name=ipso --all-containers --tail=80 || true
}

cleanup() {
  local code=$?
  if [[ -n "${kind_pid}" ]] && kill -0 "$kind_pid" 2>/dev/null; then
    kill "$kind_pid" 2>/dev/null || true
    wait "$kind_pid" 2>/dev/null || true
  fi
  if (( code != 0 )); then
    dump
    if [[ -f "$out/kind.log" ]]; then
      echo "---- kind ----" >&2
      cat "$out/kind.log" >&2 || true
    fi
  fi
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  docker rm -f "$registry_name" >/dev/null 2>&1 || true
  exit "$code"
}

wait_registry() {
  local attempt
  for attempt in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:5000/v2/ >/dev/null; then
      return
    fi
    sleep 1
  done
  echo "the local registry did not answer after ${attempt} tries" >&2
  docker logs "$registry_name" >&2 || true
  exit 1
}

digest_of() {
  local ref=$1 got
  got=$(crane digest "$ref")
  got=${got##*@}
  if [[ ! "$got" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "no digest for ${ref} (${got})" >&2
    exit 1
  fi
  printf '%s\n' "$got"
}

require_same_digest() {
  local got=$1 want=$2 what=$3
  if [[ "$got" != "$want" ]]; then
    echo "${what} digest changed from ${want} to ${got}" >&2
    exit 1
  fi
}

write_sbom() {
  local tag=$1 dest=$2
  syft "docker:${tag}" -o "cyclonedx-json=${dest}"
  python3 - "$dest" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
doc = json.loads(path.read_text())
if doc.get("bomFormat") != "CycloneDX":
    raise SystemExit(f"{path} is not CycloneDX")
PY
}

sign_one() {
  local remote=$1 digest=$2 name=$3
  local ref="${remote}@${digest}"
  cosign sign --yes --allow-http-registry \
    --bundle "${stage}/signatures/${name}.sigstore.json" \
    "$ref"
  cosign attest --yes --allow-http-registry --type cyclonedx \
    --predicate "${stage}/sbom/${name}.cdx.json" \
    --bundle "${stage}/signatures/${name}.att.sigstore.json" \
    "$ref"
  cosign save --allow-http-registry --dir "${stage}/images/${name}" "$ref"
}

offline() {
  docker run --rm --network none \
    --tmpfs /tmp \
    -e HOME=/tmp \
    -v "$(command -v cosign)":/cosign:ro \
    -v "${extract}":/work:ro \
    --entrypoint /cosign \
    "${server_repo}:airgap" \
    "$@"
}

verify_offline() {
  local name digest
  chmod -R a+rX "$extract"
  for name in ipso-server postgres nginx; do
    offline verify --local-image "/work/images/${name}" \
      --trusted-root /work/trusted-root.json \
      --certificate-identity-regexp "$identity" \
      --certificate-oidc-issuer "$issuer"
    offline verify-attestation --local-image "/work/images/${name}" --type cyclonedx \
      --trusted-root /work/trusted-root.json \
      --certificate-identity-regexp "$identity" \
      --certificate-oidc-issuer "$issuer"
  done
  local chart
  chart=$(find "${extract}/chart" -name '*.tgz' -print -quit)
  if [[ -z "$chart" ]]; then
    echo "the tar has no chart archive" >&2
    exit 1
  fi
  offline verify-blob \
    --bundle /work/signatures/chart.sigstore.json \
    --trusted-root /work/trusted-root.json \
    --certificate-identity-regexp "$identity" \
    --certificate-oidc-issuer "$issuer" \
    "/work/${chart#"${extract}/"}"
}

check_pointers() {
  python3 - "$extract/airgap-values.yaml" "$extract/deploy/bundle/compose.yaml" "$server_digest" <<'PY'
import pathlib, sys
values, compose, digest = sys.argv[1:]
if f'digest: "{digest}"' not in pathlib.Path(values).read_text():
    raise SystemExit("airgap-values.yaml does not name the signed server digest")
body = pathlib.Path(compose).read_text()
if f"ghcr.io/ipsofacto-io/ipso-server@{digest}" not in body:
    raise SystemExit("the Compose file does not name the signed server digest")
if "build:" in body:
    raise SystemExit("the Compose file still has a build")
PY
}

assert_archive() {
  tar -tf "$archive" | sed 's#^\./##' >"$out/listing"
  local need
  for need in \
    sbom/ipso-server.cdx.json \
    sbom/postgres.cdx.json \
    sbom/nginx.cdx.json \
    signatures/ipso-server.sigstore.json \
    signatures/ipso-server.att.sigstore.json \
    signatures/postgres.sigstore.json \
    signatures/postgres.att.sigstore.json \
    signatures/nginx.sigstore.json \
    signatures/nginx.att.sigstore.json \
    signatures/chart.sigstore.json \
    trusted-root.json \
    images/ipso-server/oci-layout \
    images/ipso-server/index.json \
    images/postgres/oci-layout \
    images/postgres/index.json \
    images/nginx/oci-layout \
    images/nginx/index.json \
    airgap-values.yaml \
    deploy/bundle/compose.yaml \
    deploy/compose/postgres-init.sh \
    deploy/compose/nginx.conf
  do
    if ! grep -Fxq "$need" "$out/listing"; then
      echo "the tar is missing ${need}" >&2
      exit 1
    fi
  done
  if grep -E 'dexidp|kindest' "$out/listing"; then
    echo "the tar contains a test-only image" >&2
    exit 1
  fi
  if ! grep -Eq '^chart/[^/]+\.tgz$' "$out/listing"; then
    echo "the tar is missing the chart archive" >&2
    exit 1
  fi
  python3 - "$extract/sbom/ipso-server.cdx.json" "$extract/sbom/postgres.cdx.json" "$extract/sbom/nginx.cdx.json" <<'PY'
import json, pathlib, sys
for arg in sys.argv[1:]:
    doc = json.loads(pathlib.Path(arg).read_text())
    if doc.get("bomFormat") != "CycloneDX":
        raise SystemExit(f"{arg} is not CycloneDX")
PY
}

import_layout() {
  local dir=$1 tar_in
  tar_in=$(mktemp)
  tar -C "$dir" -cf "$tar_in" .
  docker cp "$tar_in" "${cluster}-control-plane:/tmp/airgap-import.tar"
  rm -f "$tar_in"
  # The layout names the image with a cosign annotation, not a repository. --digests
  # records repository-independent name@digest so the chart reference can be tagged.
  docker exec "${cluster}-control-plane" ctr -n k8s.io images import --all-platforms --digests /tmp/airgap-import.tar
  docker exec "${cluster}-control-plane" rm -f /tmp/airgap-import.tar
}

tag_digest() {
  local digest=$1 name=$2 src
  if docker exec "${cluster}-control-plane" ctr -n k8s.io images ls | awk -v want="$name" '$1 == want { found = 1 } END { exit !found }'; then
    return
  fi
  src=$(docker exec "${cluster}-control-plane" ctr -n k8s.io images ls | awk -v d="$digest" 'index($0, d) { print $1; exit }')
  if [[ -z "$src" ]]; then
    echo "kind has no image for ${digest}" >&2
    docker exec "${cluster}-control-plane" ctr -n k8s.io images ls >&2
    exit 1
  fi
  docker exec "${cluster}-control-plane" ctr -n k8s.io images tag "$src" "$name" >/dev/null
  if ! docker exec "${cluster}-control-plane" ctr -n k8s.io images ls | awk -v want="$name" '$1 == want { found = 1 } END { exit !found }'; then
    echo "kind did not keep ${name}" >&2
    docker exec "${cluster}-control-plane" ctr -n k8s.io images ls >&2
    exit 1
  fi
}

cut_egress() {
  docker exec "${cluster}-control-plane" iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -j REJECT
  docker exec "${cluster}-control-plane" iptables -A FORWARD -p tcp -m multiport --dports 80,443 -j REJECT
  if docker exec "${cluster}-control-plane" sh -c 'command -v ip6tables >/dev/null'; then
    docker exec "${cluster}-control-plane" ip6tables -A OUTPUT -p tcp -m multiport --dports 80,443 -j REJECT
    docker exec "${cluster}-control-plane" ip6tables -A FORWARD -p tcp -m multiport --dports 80,443 -j REJECT
  fi
}

wait_health() {
  local pf code ok
  kubectl -n ipso port-forward svc/ipso-front 18080:8080 >/tmp/ipso-airgap-port-forward.log 2>&1 &
  pf=$!
  ok=0
  for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/healthz || true)
    if [[ "$code" == "204" ]]; then
      ok=1
      break
    fi
    sleep 2
  done
  kill "$pf" 2>/dev/null || true
  wait "$pf" 2>/dev/null || true
  if (( ok != 1 )); then
    echo "the front did not return 204 from /healthz" >&2
    cat /tmp/ipso-airgap-port-forward.log >&2 || true
    exit 1
  fi
}

wait_rollout() {
  kubectl -n ipso rollout status statefulset/ipso-postgresql --timeout=10m
  kubectl -n ipso rollout status deploy/ipso-api --timeout=10m
  kubectl -n ipso rollout status deploy/ipso-worker --timeout=10m
  kubectl -n ipso rollout status deploy/ipso-front --timeout=10m
}

refuse_foreign_image() {
  kubectl -n ipso apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: not-in-bundle
  namespace: ipso
spec:
  restartPolicy: Never
  containers:
    - name: missing
      image: busybox:1.36
      imagePullPolicy: Always
      command: ["true"]
EOF
  local reason=""
  for _ in $(seq 1 40); do
    reason=$(kubectl -n ipso get pod not-in-bundle -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || true)
    if [[ "$reason" == "ErrImagePull" || "$reason" == "ImagePullBackOff" ]]; then
      kubectl -n ipso delete pod not-in-bundle --wait=false >/dev/null
      return
    fi
    sleep 2
  done
  echo "a pod outside the tar reached ${reason:-no waiting reason}, want ErrImagePull" >&2
  kubectl -n ipso describe pod not-in-bundle >&2 || true
  exit 1
}

install_from_tar() {
  import_layout "${extract}/images/ipso-server"
  import_layout "${extract}/images/postgres"
  import_layout "${extract}/images/nginx"
  tag_digest "$server_digest" "${server_repo}@${server_digest}"
  tag_digest "$pg" "postgres@${pg}"
  tag_digest "$pg" "docker.io/library/postgres@${pg}"
  tag_digest "$ngx" "nginxinc/nginx-unprivileged@${ngx}"
  tag_digest "$ngx" "docker.io/nginxinc/nginx-unprivileged@${ngx}"

  kubectl create namespace ipso
  local certs dex_config dex_image
  certs=$(mktemp -d)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj "/CN=ipso airgap test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
    -keyout "$certs/ca.key" -out "$certs/ca.pem"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=dex" -keyout "$certs/dex.key" -out "$certs/dex.csr"
  printf '%s\n' \
    "subjectAltName=DNS:dex,DNS:dex.ipso,DNS:dex.ipso.svc,DNS:dex.ipso.svc.cluster.local" \
    "basicConstraints=critical,CA:FALSE" \
    "extendedKeyUsage=serverAuth" >"$certs/dex.ext"
  openssl x509 -req -in "$certs/dex.csr" -CA "$certs/ca.pem" -CAkey "$certs/ca.key" \
    -CAcreateserial -days 1 -extfile "$certs/dex.ext" -out "$certs/dex.crt"
  rm -f "$certs/ca.key" "$certs/dex.csr" "$certs/dex.ext"

  kubectl -n ipso create secret generic ipso-ci \
    --from-literal=postgres-password="$POSTGRES_PASSWORD" \
    --from-literal=migrate-password="$IPSO_MIGRATE_PASSWORD" \
    --from-literal=app-password="$IPSO_APP_PASSWORD" \
    --from-literal=database-url="postgres://ipso_app:${IPSO_APP_PASSWORD}@ipso-postgresql:5432/ipso?sslmode=disable" \
    --from-literal=migrate-database-url="postgres://ipso_migrate:${IPSO_MIGRATE_PASSWORD}@ipso-postgresql:5432/ipso?sslmode=disable" \
    --from-file=oidc-ca.pem="$certs/ca.pem"
  kubectl -n ipso create secret generic ipso-ci-kek \
    --from-literal=tenant-kek="$IPSO_TENANT_KEK"
  kubectl -n ipso create secret tls dex-tls --cert="$certs/dex.crt" --key="$certs/dex.key"
  kubectl -n ipso create secret generic dex-env \
    --from-literal=IPSO_API_CLIENT_SECRET="$IPSO_API_CLIENT_SECRET" \
    --from-literal=IPSO_OTHER_CLIENT_SECRET="$IPSO_OTHER_CLIENT_SECRET" \
    --from-literal=IPSO_LOGIN_DEX_SECRET="$IPSO_LOGIN_DEX_SECRET" \
    --from-literal=IPSO_DEX_USER="$IPSO_DEX_USER" \
    --from-literal=IPSO_DEX_PASSWORD="$IPSO_DEX_PASSWORD"

  dex_config=$(mktemp)
  sed \
    -e 's#https://dex:5556/dex#https://dex.ipso.svc.cluster.local:5556/dex#' \
    -e 's#/certs/dex.crt#/certs/tls.crt#' \
    -e 's#/certs/dex.key#/certs/tls.key#' \
    deploy/compose/dex.yaml >"$dex_config"
  kubectl -n ipso create configmap dex --from-file=dex.yaml="$dex_config"
  dex_image=$(awk '/image: ghcr.io\/dexidp\/dex/ { print $2; exit }' compose.yaml)
  kubectl -n ipso apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: dex
  namespace: ipso
spec:
  selector:
    app: dex
  ports:
    - name: https
      port: 5556
      targetPort: https
    - name: health
      port: 5558
      targetPort: health
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dex
  namespace: ipso
spec:
  replicas: 1
  selector:
    matchLabels:
      app: dex
  template:
    metadata:
      labels:
        app: dex
    spec:
      automountServiceAccountToken: false
      containers:
        - name: dex
          image: ${dex_image}
          imagePullPolicy: IfNotPresent
          args: ["dex", "serve", "/etc/dex/dex.yaml"]
          env:
            - name: DEX_EXPAND_ENV
              value: "true"
          envFrom:
            - secretRef:
                name: dex-env
          ports:
            - name: https
              containerPort: 5556
            - name: health
              containerPort: 5558
          readinessProbe:
            httpGet:
              path: /healthz
              port: health
          volumeMounts:
            - name: config
              mountPath: /etc/dex
              readOnly: true
            - name: tls
              mountPath: /certs
              readOnly: true
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: config
          configMap:
            name: dex
        - name: tls
          secret:
            secretName: dex-tls
            defaultMode: 0644
        - name: tmp
          emptyDir: {}
EOF
  kubectl -n ipso rollout status deploy/dex --timeout=300s

  cut_egress

  local chart ci_values
  chart=$(find "${extract}/chart" -name '*.tgz' -print -quit)
  ci_values=$(mktemp)
  cat >"$ci_values" <<EOF
existingSecret: ipso-ci
tenantID: ${IPSO_TENANT_ID}
oidc:
  issuer: https://dex.ipso.svc.cluster.local:5556/dex
  audience: ipso-api
  caSecretKey: oidc-ca.pem
bootstrap:
  enabled: true
  tenantName: local
  person: ${IPSO_SEED_PRINCIPAL_ID}
  personName: Local developer
  subject: ${IPSO_SEED_SUBJECT}
  kekSecret: ipso-ci-kek
EOF
  helm upgrade --install ipso "$chart" --namespace ipso \
    -f "${extract}/airgap-values.yaml" \
    -f "$ci_values" \
    --timeout 15m
  wait_rollout
  wait_health
  refuse_foreign_image
}

pack() {
  mkdir -p "$stage/signatures" "$stage/sbom" "$stage/images" "$stage/chart" \
    "$stage/deploy/bundle" "$stage/deploy/compose"
  docker build --provenance=false --sbom=false -t "${server_repo}:airgap" "$root"
  docker pull "postgres@${pg}"
  docker pull "nginxinc/nginx-unprivileged@${ngx}"
  docker tag "postgres@${pg}" ipso-airgap-postgres:pinned
  docker tag "nginxinc/nginx-unprivileged@${ngx}" ipso-airgap-nginx:pinned

  docker tag "${server_repo}:airgap" 127.0.0.1:5000/ipso-server:airgap
  docker push 127.0.0.1:5000/ipso-server:airgap
  server_digest=$(digest_of 127.0.0.1:5000/ipso-server:airgap)
  crane copy "postgres@${pg}" 127.0.0.1:5000/postgres:pinned
  crane copy "nginxinc/nginx-unprivileged@${ngx}" 127.0.0.1:5000/nginx:pinned
  require_same_digest "$(digest_of 127.0.0.1:5000/postgres:pinned)" "$pg" postgres
  require_same_digest "$(digest_of 127.0.0.1:5000/nginx:pinned)" "$ngx" nginx

  write_sbom "${server_repo}:airgap" "${stage}/sbom/ipso-server.cdx.json"
  write_sbom ipso-airgap-postgres:pinned "${stage}/sbom/postgres.cdx.json"
  write_sbom ipso-airgap-nginx:pinned "${stage}/sbom/nginx.cdx.json"
  cosign trusted-root create --with-default-services --out "${stage}/trusted-root.json"

  sign_one 127.0.0.1:5000/ipso-server "$server_digest" ipso-server
  sign_one 127.0.0.1:5000/postgres "$pg" postgres
  sign_one 127.0.0.1:5000/nginx "$ngx" nginx

  helm package charts/ipso --destination "${stage}/chart"
  local chart
  chart=$(find "${stage}/chart" -name '*.tgz' -print -quit)
  cosign sign-blob --yes --bundle "${stage}/signatures/chart.sigstore.json" "$chart"

  python3 - "$root/deploy/bundle/compose.yaml" "${stage}/deploy/bundle/compose.yaml" "$server_digest" <<'PY'
import pathlib, sys
src, dest, digest = sys.argv[1:]
text = pathlib.Path(src).read_text()
old = """x-ipso-server: &ipso-server
  build:
    context: ../..
    dockerfile: Dockerfile
  image: ipso-server:bundle
"""
new = f"""x-ipso-server: &ipso-server
  image: ghcr.io/ipsofacto-io/ipso-server@{digest}
"""
if old not in text:
    raise SystemExit("the Compose anchor changed; the air-gap rewrite no longer matches")
text = text.replace(old, new, 1)
text = text.replace(" up --build`", " up`")
old_note = (
    "# PostgreSQL and the front are pinned by digest. The server image is built from this repository\n"
    "# until the release workflow publishes one.\n"
)
new_note = "# PostgreSQL, the front, and the server image are pinned by digest. This file has no build.\n"
if old_note not in text:
    raise SystemExit("the Compose header changed; the air-gap rewrite no longer matches")
text = text.replace(old_note, new_note, 1)
if "build:" in text:
    raise SystemExit("the air-gap Compose file still has a build")
path = pathlib.Path(dest)
path.write_text(text)
PY
  cp deploy/bundle/.env.example "${stage}/deploy/bundle/.env.example"
  cp deploy/compose/postgres-init.sh "${stage}/deploy/compose/postgres-init.sh"
  cp deploy/compose/nginx.conf "${stage}/deploy/compose/nginx.conf"
  cat >"${stage}/airgap-values.yaml" <<EOF
image:
  repository: ${server_repo}
  digest: "${server_digest}"
EOF

  local env_file rendered
  env_file=$(mktemp)
  cat >"$env_file" <<'EOF'
POSTGRES_PASSWORD=airgap-config
IPSO_MIGRATE_PASSWORD=airgap-config
IPSO_APP_PASSWORD=airgap-config
IPSO_TENANT_ID=00000000-0000-4000-8000-000000000001
IPSO_OIDC_ISSUER=https://issuer.example
IPSO_API_AUDIENCE=ipso-api
IPSO_TENANT_NAME=local
IPSO_PERSON_ID=00000000-0000-4000-8000-0000000000a1
IPSO_PERSON_NAME=Local
IPSO_OIDC_SUBJECT=subject
IPSO_TENANT_KEK=airgap-config
EOF
  rendered=$(docker compose -f "${stage}/deploy/bundle/compose.yaml" --env-file "$env_file" config)
  if grep -q 'build:' <<<"$rendered"; then
    echo "rendered Compose still builds an image" >&2
    exit 1
  fi
  if ! grep -q "${server_repo}@${server_digest}" <<<"$rendered"; then
    echo "rendered Compose is missing the server digest" >&2
    exit 1
  fi

  tar -C "$stage" -cf "$archive" .
  docker rm -f "$registry_name" >/dev/null
}

require_tools
require_pins
rm -rf "$out"
mkdir -p "$out"
trap cleanup EXIT

docker run -d --name "$registry_name" -p 127.0.0.1:5000:5000 "$registry_image" >/dev/null
kind create cluster --name "$cluster" --image "$kind_node" >"$out/kind.log" 2>&1 &
kind_pid=$!
wait_registry
pack
if ! wait "$kind_pid"; then
  echo "kind did not start" >&2
  exit 1
fi
kind_pid=

rm -rf "$extract"
mkdir -p "$extract"
tar -C "$extract" -xf "$archive"
assert_archive
verify_offline
check_pointers

set -a
# shellcheck disable=SC1091
. ./.env.example
set +a
install_from_tar
echo "air-gap tar ${archive}"
