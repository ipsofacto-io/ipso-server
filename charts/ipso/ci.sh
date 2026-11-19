#!/usr/bin/env bash
# Lint the chart, and optionally install it on kind and upgrade across the two highest goose files.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
mode=${1:-lint}
cluster=ipso-chart

lint() {
  cmp charts/ipso/files/postgres-init.sh deploy/compose/postgres-init.sh
  local pg ngx
  pg=$(sed -n 's/.*image: postgres:.*@//p' compose.yaml | head -1)
  ngx=$(sed -n 's/.*image: nginxinc.*@//p' compose.yaml | head -1)
  grep -q "$pg" deploy/bundle/compose.yaml
  grep -q "$pg" charts/ipso/values.yaml
  grep -q "$ngx" deploy/bundle/compose.yaml
  grep -q "$ngx" charts/ipso/values.yaml

  local err out
  err=$(mktemp)
  if helm template ipso charts/ipso >"$err" 2>&1; then
    echo "the default render succeeded and it must fail closed" >&2
    exit 1
  fi
  grep -q "existingSecret is required" "$err"

  helm lint charts/ipso -f charts/ipso/ci/values.yaml
  out=$(mktemp)
  helm template ipso charts/ipso -f charts/ipso/ci/values.yaml >"$out"
  python3 charts/ipso/ci/check_render.py "$out"
  if grep -q 'kubernetes.io/metadata.name: "idp"' "$out"; then
    echo "the default render opens an issuer namespace" >&2
    exit 1
  fi
  local ns
  ns=$(mktemp)
  helm template ipso charts/ipso -f charts/ipso/ci/values.yaml \
    --set-string oidc.namespace=idp --set oidc.port=8443 >"$ns"
  grep -q 'kubernetes.io/metadata.name: "idp"' "$ns"
  grep -q 'port: 8443' "$ns"
  helm template ipso charts/ipso \
    -f charts/ipso/ci/values.yaml \
    -f charts/ipso/ci/bootstrap-values.yaml >"$out"
  python3 charts/ipso/ci/check_render.py "$out" --bootstrap
}

digest_of() {
  local ref=$1 line
  line=$(docker exec "${cluster}-control-plane" ctr -n k8s.io images ls | awk -v ref="$ref" '$1 == ref { print; exit }')
  if [[ -z "$line" ]]; then
    echo "kind has no image matching ${ref}" >&2
    docker exec "${cluster}-control-plane" ctr -n k8s.io images ls >&2
    exit 1
  fi
  if [[ "$line" == *index* ]]; then
    echo "kind loaded ${ref} as an attestation index, not a runnable manifest" >&2
    echo "$line" >&2
    exit 1
  fi
  awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^sha256:/) { print $i; exit } }' <<<"$line"
}

# kind load stores the image by tag. containerd 2 answers a digest pull only when that
# repository@digest name exists, so the chart reference has to be tagged explicitly.
pin_loaded_image() {
  local ref=$1 digest repo name
  digest=$(digest_of "$ref")
  repo=${ref%:*}
  name="${repo}@${digest}"
  docker exec "${cluster}-control-plane" ctr -n k8s.io images tag "$ref" "$name" >/dev/null
  if ! docker exec "${cluster}-control-plane" ctr -n k8s.io images ls | awk -v want="$name" '$1 == want { found = 1 } END { exit !found }'; then
    echo "kind has ${ref} but not ${name}" >&2
    docker exec "${cluster}-control-plane" ctr -n k8s.io images ls >&2
    exit 1
  fi
  echo "$digest"
}

dump() {
  kubectl -n ipso get pods -o wide || true
  kubectl -n ipso get events --sort-by=.lastTimestamp || true
  kubectl -n ipso describe pods || true
  kubectl -n ipso logs -l app.kubernetes.io/name=ipso --all-containers --tail=100 || true
}

wait_health() {
  local pf code ok
  kubectl -n ipso port-forward svc/ipso-front 18080:8080 >/tmp/ipso-port-forward.log 2>&1 &
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
    cat /tmp/ipso-port-forward.log >&2 || true
    dump
    exit 1
  fi
}

wait_rollout() {
  kubectl -n ipso rollout status statefulset/ipso-postgresql --timeout=10m
  kubectl -n ipso rollout status deploy/ipso-api --timeout=10m
  kubectl -n ipso rollout status deploy/ipso-worker --timeout=10m
  kubectl -n ipso rollout status deploy/ipso-front --timeout=10m
}

goose_version() {
  # goose_db_version is owned by the migration role. The application role has no grant on it.
  kubectl -n ipso exec ipso-postgresql-0 -- \
    env PGPASSWORD="$IPSO_MIGRATE_PASSWORD" \
    psql --host=127.0.0.1 --username=ipso_migrate --dbname=ipso --tuples-only --no-align \
    --command="SELECT max(version_id) FROM goose_db_version"
}

migration_numbers() {
  find internal/migrate/migrations -name '*.sql' -print \
    | sed -n 's#.*/0*\([0-9][0-9]*\)_.*#\1#p' \
    | sort -n
}

refuse() {
  local name=$1 role=$2
  kubectl -n ipso delete pod "$name" --ignore-not-found --wait=true >/dev/null
  kubectl -n ipso apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  namespace: ipso
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: server
      image: ghcr.io/ipsofacto-io/ipso-server@${full_digest}
      imagePullPolicy: IfNotPresent
      command: ["/usr/local/bin/ipso-server", "--role=${role}"]
      env:
        - name: IPSO_DATABASE_URL
          value: postgres://ipso_migrate:${IPSO_MIGRATE_PASSWORD}@ipso-postgresql:5432/ipso?sslmode=disable
        - name: IPSO_TENANT_ID
          value: "${IPSO_TENANT_ID}"
        - name: IPSO_OIDC_ISSUER
          value: https://dex.ipso.svc.cluster.local:5556/dex
        - name: IPSO_API_AUDIENCE
          value: ipso-api
        - name: SSL_CERT_FILE
          value: /certs/oidc-ca.pem
      volumeMounts:
        - name: ca
          mountPath: /certs
          readOnly: true
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
  volumes:
    - name: ca
      secret:
        secretName: ipso-ci
        items:
          - key: oidc-ca.pem
            path: oidc-ca.pem
EOF
  local phase=""
  for _ in $(seq 1 60); do
    phase=$(kubectl -n ipso get pod "$name" -o jsonpath='{.status.phase}')
    if [[ "$phase" == "Failed" || "$phase" == "Succeeded" ]]; then
      break
    fi
    sleep 2
  done
  local logs
  logs=$(kubectl -n ipso logs "$name" || true)
  printf '%s\n' "$logs"
  if [[ "$phase" != "Failed" ]] || ! grep -q "refusing to start" <<<"$logs"; then
    echo "${name} did not refuse the migration role (phase ${phase})" >&2
    exit 1
  fi
}

install_on_kind() {
  lint
  command -v kind >/dev/null
  command -v kubectl >/dev/null
  command -v docker >/dev/null
  command -v openssl >/dev/null

  local copy n2_image full_image
  copy=$(mktemp -d)
  tar -C "$root" --exclude .git -cf - . | tar -C "$copy" -xf -
  find "$copy/internal/migrate/migrations" -name '*.sql' -print | sort | tail -2 | xargs rm -f

  # The node image pull overlaps the two server builds. The job budget is 30 minutes.
  kind create cluster --name "$cluster" \
    --image "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5" &
  local kind_pid=$!
  # Provenance would publish an attestation index. kind would then pin that index, and the
  # kubelet cannot run it, so the chart's digest would sit in ImagePullBackOff.
  docker build --provenance=false --sbom=false -t ghcr.io/ipsofacto-io/ipso-server:ci "$root"
  docker build --provenance=false --sbom=false -t ghcr.io/ipsofacto-io/ipso-server:n-2 "$copy"
  wait "$kind_pid"
  kind load docker-image ghcr.io/ipsofacto-io/ipso-server:ci --name "$cluster"
  kind load docker-image ghcr.io/ipsofacto-io/ipso-server:n-2 --name "$cluster"
  n2_image=$(pin_loaded_image ghcr.io/ipsofacto-io/ipso-server:n-2)
  full_image=$(pin_loaded_image ghcr.io/ipsofacto-io/ipso-server:ci)
  echo "n-2 image ${n2_image}"
  echo "full image ${full_image}"
  full_digest=$full_image

  set -a
  # shellcheck disable=SC1091
  . ./.env.example
  set +a

  kubectl create namespace ipso
  local certs
  certs=$(mktemp -d)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj "/CN=ipso chart test CA" \
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

  local dex_config dex_image
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

  write_values() {
    local digest=$1 dest=$2
    cat >"$dest" <<EOF
image:
  repository: ghcr.io/ipsofacto-io/ipso-server
  digest: "${digest}"
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
  }

  local values_n2 values_full start elapsed got want_n2 want_head completed
  values_n2=$(mktemp)
  values_full=$(mktemp)
  write_values "$n2_image" "$values_n2"
  write_values "$full_image" "$values_full"

  start=$(date +%s)
  # Post-install hooks run after the workloads exist. --wait would block on the api before migrate.
  helm upgrade --install ipso charts/ipso --namespace ipso -f "$values_n2" --timeout 15m
  wait_rollout
  wait_health
  elapsed=$(( $(date +%s) - start ))
  if (( elapsed > 1800 )); then
    echo "install reached /healthz in ${elapsed}s, which is over 30 minutes" >&2
    exit 1
  fi
  got=$(goose_version | tr -d '[:space:]')
  want_n2=$(migration_numbers | tail -3 | head -1)
  if [[ "$got" != "$want_n2" ]]; then
    echo "schema after the N-2 install is ${got}, want ${want_n2}" >&2
    exit 1
  fi

  helm upgrade ipso charts/ipso --namespace ipso -f "$values_full" --timeout 15m
  wait_rollout
  wait_health
  got=$(goose_version | tr -d '[:space:]')
  want_head=$(migration_numbers | tail -1)
  if [[ "$got" != "$want_head" ]]; then
    echo "schema after the upgrade is ${got}, want ${want_head}" >&2
    exit 1
  fi

  local attempt
  for attempt in $(seq 1 45); do
    completed=$(kubectl -n ipso exec ipso-postgresql-0 -- \
      env PGPASSWORD="$IPSO_APP_PASSWORD" \
      psql --host=127.0.0.1 --username=ipso_app --dbname=ipso --tuples-only --no-align \
      --command="SELECT count(DISTINCT kind) FROM river.river_job WHERE kind IN ('waiver_notices', 'premise_sweep', 'tenant_export_sweep', 'chat_digests') AND state = 'completed'")
    completed=$(echo "$completed" | tr -d '[:space:]')
    if [[ "${completed}" -ge 4 ]]; then
      break
    fi
    if (( attempt == 45 )); then
      echo "the worker did not complete its sweeps" >&2
      dump
      exit 1
    fi
    sleep 2
  done

  refuse refuse-api api
  refuse refuse-worker worker
}

case "$mode" in
  lint) lint ;;
  kind)
    trap 'code=$?; if (( code != 0 )); then dump; fi; kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; exit "$code"' EXIT
    install_on_kind
    ;;
  *)
    echo "usage: charts/ipso/ci.sh lint|kind" >&2
    exit 2
    ;;
esac
