#!/usr/bin/env bash
# Pack the ADR-0140 install into one tar, sign it, and install that tar on kind
# with the node's registry egress cut (ADR-0142, ADR-0143).
# Keyless signing needs the Actions OIDC token. There is no second key.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

cluster=ipso-airgap
# zot v2.1.23. cosign 3.1.4 stores the bundle as an OCI referrer.
# The distribution registry image through 3.1.2 does not implement that API, so cosign save would not see the bundles.
# The binary serves that registry. A container pull is not part of signing.
server_repo=ghcr.io/ipsofacto-io/ipso-server
kind_node=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
issuer=https://token.actions.githubusercontent.com

expected_identity() {
  local ref='refs/heads/main'
  if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" ]]; then
    if [[ -n "${GITHUB_HEAD_REPO:-}" && "${GITHUB_HEAD_REPO}" != "${GITHUB_REPOSITORY:-}" ]]; then
      echo "refusing keyless signing for fork pull request: ${GITHUB_HEAD_REPO}" >&2
      exit 1
    fi
    if [[ ! "${GITHUB_REF:-}" =~ ^refs/pull/[0-9]+/(merge|head)$ ]]; then
      echo "unexpected pull_request GITHUB_REF: ${GITHUB_REF:-}" >&2
      exit 1
    fi
    ref=$GITHUB_REF
  elif [[ -n "${GITHUB_REF:-}" && "${GITHUB_REF}" != "refs/heads/main" ]]; then
    echo "refusing non-main ref outside pull_request CI: ${GITHUB_REF}" >&2
    exit 1
  fi
  printf '^https://github\\.com/ipsofacto-io/ipso-server/\\.github/workflows/ci\\.yml@%s$\n' "$ref"
}

identity=$(expected_identity)

out=${RUNNER_TEMP:-/tmp}/ipso-airgap
stage=$out/stage
extract=$out/extract
archive=${AIRGAP_ARCHIVE:-$out/ipso-airgap.tar}
kind_pid=
heartbeat_pid=
zot_pid=

require_tools() {
  local want=${1:-all} cmd
  for cmd in docker helm kind kubectl cosign syft crane zot openssl python3 curl; do
    command -v "$cmd" >/dev/null
  done
  if [[ "$want" == "all" || "$want" == "verify" || "$want" == "install" ]]; then
    command -v unshare >/dev/null
  fi
  if [[ "$want" == "all" || "$want" == "sign" ]]; then
    if [[ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" || -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]]; then
      echo "keyless signing needs the Actions OIDC token" >&2
      exit 1
    fi
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

# kubectl and kind talk to a daemon that may be stuck in uninterruptible sleep.
# Waiting for that daemon holds the step open, and a cancelled job drops the log.
dump_quick() {
  local pid
  {
    kubectl -n ipso get pods -o wide || true
    kubectl -n ipso get events --sort-by=.lastTimestamp || true
    kubectl -n ipso describe pods || true
    kubectl -n ipso logs -l app.kubernetes.io/name=ipso --all-containers --tail=80 || true
  } >"$out/dump.txt" 2>&1 &
  pid=$!
  for _ in $(seq 1 10); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" || true
      cat "$out/dump.txt" >&2 || true
      return
    fi
    sleep 2
  done
  echo "kubectl did not return" >&2
  kill -KILL "$pid" 2>/dev/null || true
  cat "$out/dump.txt" >&2 || true
}

cleanup() {
  local code=$? pid del
  for pid in "$heartbeat_pid" "$kind_pid" "$zot_pid"; do
    if [[ -n "$pid" ]]; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  done
  if (( code != 0 )) && [[ "${AIRGAP_BAIL:-}" != 1 ]]; then
    if [[ -f "$out/kind.log" ]]; then
      dump_quick
      echo "---- kind ----" >&2
      tail -n 80 "$out/kind.log" >&2 || true
    fi
    if [[ -f "$out/zot.log" ]]; then
      echo "---- zot ----" >&2
      tail -n 80 "$out/zot.log" >&2 || true
    fi
    if [[ -f "$out/bounded.log" ]]; then
      echo "---- command ----" >&2
      tail -n 80 "$out/bounded.log" >&2 || true
    fi
  fi
  if [[ "${AIRGAP_BAIL:-}" != 1 && -f "$out/kind.log" ]]; then
    kind delete cluster --name "$cluster" >/dev/null 2>&1 &
    del=$!
    for _ in $(seq 1 8); do
      if ! kill -0 "$del" 2>/dev/null; then
        break
      fi
      sleep 1
    done
    kill -KILL "$del" 2>/dev/null || true
  fi
  exit "$code"
}

wait_registry() {
  local attempt
  for attempt in $(seq 1 30); do
    if curl -fsS --max-time 2 http://127.0.0.1:5000/v2/ >/dev/null; then
      return
    fi
    sleep 1
  done
  echo "the local registry did not answer after ${attempt} tries" >&2
  cat "$out/zot.log" >&2 || true
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
  local source=$1 dest=$2
  phase "sbom ${dest}"
  bounded 2m syft "$source" -o "cyclonedx-json=${dest}"
  python3 - "$dest" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
doc = json.loads(path.read_text())
if doc.get("bomFormat") != "CycloneDX":
    raise SystemExit(f"{path} is not CycloneDX")
PY
}

phase() {
  local msg
  msg="airgap: $* ($(date -u +%H:%M:%S))"
  echo "$msg" >&2
  echo "$msg" >"$out/phase"
  # The runner records notices while the step is still going. The job log is not
  # downloadable until the runner exits, and a job cancel drops that log.
  echo "::notice::${msg}"
}

heartbeat() {
  local msg="" last="" ticks=0
  while true; do
    msg="airgap: starting"
    if [[ -f "$out/phase" ]]; then
      msg=$(cat "$out/phase")
    fi
    ticks=$((ticks + 1))
    if [[ "$msg" != "$last" || $((ticks % 4)) -eq 0 ]]; then
      echo "::notice::${msg}"
      last=$msg
    fi
    sleep 30
  done
}

# A child in uninterruptible sleep ignores KILL, and waiting for it holds the
# step open until the job is cancelled. A cancelled job drops the log. The child
# runs in its own session. This shell only sleeps, and it exits without waiting.
bounded() {
  local limit=$1
  shift
  local seconds=0 elapsed=0 pid rc state
  case "$limit" in
    *m) seconds=$(( ${limit%m} * 60 )) ;;
    *s) seconds=$(( ${limit%s} )) ;;
    *)
      echo "limit must end in m or s: ${limit}" >&2
      exit 1
      ;;
  esac
  : >"$out/bounded.log"
  python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' "$@" >"$out/bounded.log" 2>&1 &
  pid=$!
  while [[ -d "/proc/${pid}" ]]; do
    state=$(cat "/proc/${pid}/stat" 2>/dev/null || true)
    state=${state#*) }
    state=${state%% *}
    # A finished child is a zombie until wait. kill -0 still succeeds for it.
    if [[ -z "$state" || "$state" == "Z" ]]; then
      break
    fi
    if (( elapsed >= seconds )); then
      kill -KILL -- "-${pid}" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
      AIRGAP_BAIL=1
      echo "airgap: giving up after ${seconds}s: $*" >&2
      tail -n 100 "$out/bounded.log" >&2 || true
      if [[ -f "$out/zot.log" ]]; then
        echo "---- zot ----" >&2
        tail -n 80 "$out/zot.log" >&2 || true
      fi
      exit 124
    fi
    sleep 5
    elapsed=$((elapsed + 5))
    if (( elapsed % 15 == 0 )); then
      echo "airgap: still running (${elapsed}s, state ${state}): $*" >&2
    fi
  done
  set +e
  wait "$pid"
  rc=$?
  set -e
  return "$rc"
}

sign_ref() {
  local remote=$1 digest=$2 name=$3
  local ref="${remote}@${digest}"
  phase "sign ${name}"
  bounded 2m cosign sign --yes --allow-http-registry \
    --bundle "${stage}/signatures/${name}.sigstore.json" \
    "$ref"
  bounded 2m cosign attest --yes --allow-http-registry --type cyclonedx \
    --predicate "${stage}/sbom/${name}.cdx.json" \
    --bundle "${stage}/signatures/${name}.att.sigstore.json" \
    "$ref"
}

sign_one() {
  sign_ref "$@"
  phase "save $3"
  bounded 1m cosign save --allow-http-registry --dir "${stage}/images/$3" "${1}@${2}"
}

# The chart pins an index digest. Copying every architecture does not fit the job.
# Publish linux/amd64 for the node, then the original index bytes so the digest is unchanged.
publish_pinned() {
  local src=$1 dest=$2 pin=$3 what=$4
  phase "publish ${what}"
  python3 - "$src" "$dest" "$pin" "$what" <<'PY'
import json, os, signal, subprocess, sys, time, urllib.error, urllib.request
src, dest, pin, what = sys.argv[1:]

def run(cmd, seconds):
    proc = subprocess.Popen(cmd, start_new_session=True)
    deadline = time.monotonic() + seconds
    while True:
        rc = proc.poll()
        if rc is not None:
            if rc != 0:
                raise SystemExit(f"publish {what}: {' '.join(cmd[:4])} failed ({rc})")
            return
        if time.monotonic() >= deadline:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            print(
                f"publish {what}: {' '.join(cmd[:4])} exceeded {seconds}s",
                file=sys.stderr,
                flush=True,
            )
            os._exit(124)
        time.sleep(2)

try:
    raw = subprocess.check_output(["crane", "manifest", src], timeout=120)
except subprocess.TimeoutExpired:
    raise SystemExit(f"publish {what}: reading the manifest exceeded 2 minutes")
manifest = json.loads(raw)
media = manifest.get("mediaType", "")
host, repo = dest.split("/", 1)
base = f"http://{host}/v2/{repo}"

def put(ref_name, body, content_type):
    req = urllib.request.Request(
        f"{base}/manifests/{ref_name}",
        data=body,
        method="PUT",
        headers={"Content-Type": content_type},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            if resp.status not in (201, 202):
                raise SystemExit(f"publish {what} {ref_name}: HTTP {resp.status}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:500]
        raise SystemExit(f"publish {what} {ref_name}: HTTP {exc.code} {detail}")

if "index" in media or "list" in media:
    # zot accepts a sparse index, so the other architectures are not uploaded.
    run(["crane", "copy", "--platform", "linux/amd64", src, f"{dest}:platform"], 600)
    put(pin, raw, media)
    put("pinned", raw, media)
else:
    run(["crane", "copy", src, f"{dest}:pinned"], 600)
PY
  require_same_digest "$(digest_of "${dest}:pinned")" "$pin" "$what"
}

# Sparse OCI layout carrying the pinned index, the linux/amd64 manifest, config,
# and layers from local zot, plus the cosign referrer bundles.
write_signed_layout() {
  local src=$1 dest=$2 pin=$3 dir=$4
  phase "layout ${dir}"
  python3 - "$src" "$dest" "$pin" "$dir" <<'PY'
import hashlib, json, pathlib, subprocess, sys, urllib.request
src, dest, pin, directory = sys.argv[1:]
root = pathlib.Path(directory)
blobs = root / "blobs" / "sha256"
blobs.mkdir(parents=True)
(root / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}\n')
try:
    raw = subprocess.check_output(["crane", "manifest", src], timeout=120)
except subprocess.TimeoutExpired:
    raise SystemExit("reading the pinned manifest exceeded 2 minutes")
if "sha256:" + hashlib.sha256(raw).hexdigest() != pin:
    raise SystemExit("the source manifest is not the pinned digest")
(blobs / pin.split(":", 1)[1]).write_bytes(raw)
manifest = json.loads(raw)
host, repo = dest.split("/", 1)
base = f"http://{host}/v2/{repo}"

def fetch(url, accept=None):
    headers = {"Accept": accept} if accept else {}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()

def save_blob(digest):
    target = blobs / digest.split(":", 1)[1]
    if target.exists():
        return
    req = urllib.request.Request(f"{base}/blobs/{digest}")
    h = hashlib.sha256()
    with urllib.request.urlopen(req, timeout=180) as resp, target.open("wb") as out_f:
        while True:
            chunk = resp.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            out_f.write(chunk)
    if "sha256:" + h.hexdigest() != digest:
        raise SystemExit(f"blob digest mismatch for {digest}")

referrers = json.loads(fetch(
    f"{base}/referrers/{pin}",
    "application/vnd.oci.image.index.v1+json",
))
amd64 = [
    m for m in manifest.get("manifests", [])
    if m.get("platform", {}).get("os") == "linux"
    and m.get("platform", {}).get("architecture") == "amd64"
    and "vnd.docker.reference.type" not in (m.get("annotations") or {})
]
if len(amd64) != 1:
    raise SystemExit(f"expected one linux/amd64 manifest in {pin}, got {len(amd64)}")
plat_desc = amd64[0]
plat_body = fetch(f"{base}/manifests/{plat_desc['digest']}", plat_desc.get("mediaType"))
if "sha256:" + hashlib.sha256(plat_body).hexdigest() != plat_desc["digest"]:
    raise SystemExit(f"linux/amd64 manifest digest mismatch for {plat_desc['digest']}")
(blobs / plat_desc["digest"].split(":", 1)[1]).write_bytes(plat_body)
plat_doc = json.loads(plat_body)
save_blob(plat_doc["config"]["digest"])
for layer_desc in plat_doc.get("layers", []):
    save_blob(layer_desc["digest"])
found = False
for desc in referrers.get("manifests", []):
    body = fetch(f"{base}/manifests/{desc['digest']}", desc.get("mediaType"))
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    if digest != desc["digest"]:
        raise SystemExit(f"referrer digest mismatch for {desc['digest']}")
    (blobs / digest.split(":", 1)[1]).write_bytes(body)
    for layer in json.loads(body).get("layers", []):
        layer_body = fetch(f"{base}/blobs/{layer['digest']}")
        layer_digest = "sha256:" + hashlib.sha256(layer_body).hexdigest()
        if layer_digest != layer["digest"]:
            raise SystemExit(f"bundle blob mismatch for {layer['digest']}")
        (blobs / layer_digest.split(":", 1)[1]).write_bytes(layer_body)
        if str(layer.get("mediaType", "")).startswith("application/vnd.dev.sigstore.bundle"):
            found = True
if not found:
    raise SystemExit(f"no sigstore bundle was attached to {pin}")
index = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "manifests": [{
        "mediaType": manifest["mediaType"],
        "digest": pin,
        "size": len(raw),
        "annotations": {"kind": "dev.cosignproject.cosign/imageIndex"},
    }],
}
(root / "index.json").write_text(json.dumps(index))
PY
}

# docker run --network none hung in this step and kept the runner from exiting.
# Unshare the network namespace via sudo when available, or via a user namespace
# otherwise. Both namespaces start with no interfaces up, so any socket fails.
run_isolated() {
  local home_dir=$1
  shift
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    bounded 1m sudo env HOME="$home_dir" unshare --net -- "$@"
  else
    bounded 1m env HOME="$home_dir" unshare --user --map-root-user --net -- "$@"
  fi
}

assert_offline() {
  local home_dir=$1
  run_isolated "$home_dir" python3 -c '
import errno, socket, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    rc = sock.connect_ex(("192.0.2.1", 443))
finally:
    sock.close()
if rc not in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN):
    sys.exit(f"network namespace still has routes (connect_ex={rc})")
'
}

offline() {
  local home_dir=$1
  shift
  local cosign_bin
  cosign_bin=$(command -v cosign)
  run_isolated "$home_dir" "$cosign_bin" "$@"
}

trusted_root_path() {
  local candidate
  if [[ -n "${AIRGAP_TRUSTED_ROOT:-}" ]]; then
    if [[ ! -r "$AIRGAP_TRUSTED_ROOT" || ! -f "$AIRGAP_TRUSTED_ROOT" ]]; then
      echo "AIRGAP_TRUSTED_ROOT is not a readable file: $AIRGAP_TRUSTED_ROOT" >&2
      exit 1
    fi
    candidate="$AIRGAP_TRUSTED_ROOT"
  elif [[ -r "$out/trusted-root.json" && -f "$out/trusted-root.json" ]]; then
    candidate="$out/trusted-root.json"
  else
    echo "set AIRGAP_TRUSTED_ROOT to an out-of-band Sigstore trusted-root.json before running verify" >&2
    exit 1
  fi
  python3 - "$candidate" "$extract" <<'PY'
import pathlib, sys

root_path = pathlib.Path(sys.argv[1]).resolve()
extract_dir = pathlib.Path(sys.argv[2]).resolve()
if root_path == extract_dir or extract_dir in root_path.parents:
    raise SystemExit("out-of-band trusted root must not resolve inside the archive extraction directory")
print(root_path)
PY
}

extract_bootstrap() {
  local src_tar=$1 dest_dir=$2
  rm -rf "$dest_dir"
  mkdir -p "$dest_dir"
  python3 - "$src_tar" "$dest_dir" <<'PY'
import pathlib, sys, tarfile

archive = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2]).resolve()
allowed = {"trusted-root.json", "manifest.sha256", "signatures/manifest.sigstore.json"}
seen = set()
max_bytes = 4 * 1024 * 1024
with tarfile.open(archive) as tar:
    for member in tar.getmembers():
        clean = member.name.removeprefix("./")
        if member.name.startswith("/") or ".." in pathlib.PurePosixPath(member.name).parts:
            raise SystemExit(f"unsafe path in archive: {member.name}")
        target = (dest / member.name).resolve()
        if target != dest and dest not in target.parents:
            raise SystemExit(f"archive member escapes destination: {member.name}")
        if member.isdir():
            continue
        if not member.isfile():
            raise SystemExit(f"unsupported non-file member in archive: {member.name}")
        if clean not in allowed:
            continue
        if clean in seen:
            raise SystemExit(f"duplicate bootstrap member in archive: {clean}")
        if member.size > max_bytes:
            raise SystemExit(f"bootstrap member exceeds {max_bytes} bytes: {clean}")
        src = tar.extractfile(member)
        if src is None:
            raise SystemExit(f"empty file member in archive: {member.name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(src.read())
        seen.add(clean)
missing = sorted(allowed - seen)
if missing:
    raise SystemExit(f"archive is missing bootstrap files: {', '.join(missing)}")
PY
}

extract_verified_archive() {
  local src_tar=$1 dest_dir=$2 oob_root=$3
  python3 - "$src_tar" "$dest_dir" "$out/listing" "$oob_root" <<'PY'
import hashlib, pathlib, re, sys, tarfile

archive = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2]).resolve()
listing_out = pathlib.Path(sys.argv[3])
oob_root = pathlib.Path(sys.argv[4])
bootstrap = {"trusted-root.json", "manifest.sha256", "signatures/manifest.sigstore.json"}

dest_root = (dest / "trusted-root.json").resolve()
oob_resolved = oob_root.resolve()
if oob_resolved == dest_root or dest in oob_resolved.parents:
    raise SystemExit("out-of-band trusted root must not resolve inside the archive extraction directory")
if dest_root.read_bytes() != oob_resolved.read_bytes():
    raise SystemExit("embedded trusted-root.json does not match out-of-band trusted root")

expected = {}
line_re = re.compile(r"^([0-9a-f]{64})  (.+)$")
for raw_line in (dest / "manifest.sha256").read_text().splitlines():
    m = line_re.match(raw_line)
    if not m:
        raise SystemExit(f"malformed manifest.sha256 line: {raw_line!r}")
    digest, rel_path = m.groups()
    if rel_path.startswith("/") or ".." in pathlib.PurePosixPath(rel_path).parts:
        raise SystemExit(f"unsafe path in manifest.sha256: {rel_path}")
    if rel_path in bootstrap or rel_path in expected:
        raise SystemExit(f"unexpected or duplicate entry in manifest.sha256: {rel_path}")
    expected[rel_path] = digest

seen = set()
names = []
with tarfile.open(archive) as tar:
    for member in tar.getmembers():
        clean = member.name.removeprefix("./")
        if member.name.startswith("/") or ".." in pathlib.PurePosixPath(member.name).parts:
            raise SystemExit(f"unsafe path in archive: {member.name}")
        target = (dest / member.name).resolve()
        if target != dest and dest not in target.parents:
            raise SystemExit(f"archive member escapes destination: {member.name}")
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not member.isfile():
            raise SystemExit(f"unsupported non-file member in archive: {member.name}")
        if not clean or clean in seen:
            raise SystemExit(f"empty or duplicate member in archive: {member.name}")
        seen.add(clean)
        names.append(clean)
        if clean in bootstrap:
            continue
        want_sum = expected.get(clean)
        if want_sum is None:
            raise SystemExit(f"unlisted member in archive not covered by manifest.sha256: {clean}")
        src = tar.extractfile(member)
        if src is None:
            raise SystemExit(f"empty file member in archive: {member.name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp_target = target.with_name(f".tmp.{target.name}")
        h = hashlib.sha256()
        with tmp_target.open("wb") as out_f:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
                out_f.write(chunk)
        if h.hexdigest() != want_sum:
            tmp_target.unlink(missing_ok=True)
            raise SystemExit(f"sha256 mismatch against signed manifest.sha256 for {clean}")
        tmp_target.replace(target)

missing = sorted(set(expected) - seen)
if missing:
    raise SystemExit(f"archive is missing files listed in manifest.sha256: {', '.join(missing[:5])}")
listing_out.write_text("\n".join(names) + ("\n" if names else ""))
PY
}

verify_manifest_offline() {
  local home_dir=$1 root_file=$2
  chmod -R a+rX "$extract"
  assert_offline "$home_dir"
  phase "verify manifest"
  offline "$home_dir" verify-blob \
    --bundle "${extract}/signatures/manifest.sigstore.json" \
    --trusted-root "$root_file" \
    --certificate-identity-regexp "$identity" \
    --certificate-oidc-issuer "$issuer" \
    "${extract}/manifest.sha256"
}

verify_offline() {
  local home_dir=$1 root_file=$2 name
  chmod -R a+rX "$extract"
  assert_offline "$home_dir"
  for name in ipso-server postgres nginx; do
    phase "verify ${name}"
    offline "$home_dir" verify --local-image "${extract}/images/${name}" \
      --trusted-root "$root_file" \
      --certificate-identity-regexp "$identity" \
      --certificate-oidc-issuer "$issuer"
    offline "$home_dir" verify-attestation --local-image "${extract}/images/${name}" --type cyclonedx \
      --trusted-root "$root_file" \
      --certificate-identity-regexp "$identity" \
      --certificate-oidc-issuer "$issuer"
  done
  local chart
  chart=$(find "${extract}/chart" -name '*.tgz' -print -quit)
  if [[ -z "$chart" ]]; then
    echo "the tar has no chart archive" >&2
    exit 1
  fi
  phase "verify chart"
  offline "$home_dir" verify-blob \
    --bundle "${extract}/signatures/chart.sigstore.json" \
    --trusted-root "$root_file" \
    --certificate-identity-regexp "$identity" \
    --certificate-oidc-issuer "$issuer" \
    "$chart"
}

check_pointers() {
  python3 - "$extract" "$server_digest" "$pg" "$ngx" <<'PY'
import hashlib, json, pathlib, sys

root = pathlib.Path(sys.argv[1])
digest, pg_pin, ngx_pin = sys.argv[2:]
values = (root / "airgap-values.yaml").read_text()
if f'digest: "{digest}"' not in values:
    raise SystemExit("airgap-values.yaml does not name the signed server digest")
body = (root / "deploy/bundle/compose.yaml").read_text()
if f"ghcr.io/ipsofacto-io/ipso-server@{digest}" not in body:
    raise SystemExit("the Compose file does not name the signed server digest")
if "build:" in body:
    raise SystemExit("the Compose file still has a build")

def check_blob(blobs, dgst, label):
    path = blobs / dgst.split(":", 1)[1]
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    if "sha256:" + h.hexdigest() != dgst:
        raise SystemExit(f"{label} blob digest mismatch for {dgst}")

def verify_manifest_blobs(blobs, manifest_digest, label):
    check_blob(blobs, manifest_digest, label)
    doc = json.loads((blobs / manifest_digest.split(":", 1)[1]).read_text())
    check_blob(blobs, doc["config"]["digest"], label)
    for layer in doc.get("layers", []):
        check_blob(blobs, layer["digest"], label)

def verify_sparse_layout(layout_dir, pin, label):
    idx = json.loads((layout_dir / "index.json").read_text())
    entries = idx.get("manifests") or []
    if len(entries) != 1 or entries[0].get("digest") != pin:
        raise SystemExit(f"{label} layout index does not point to {pin}")
    blobs = layout_dir / "blobs" / "sha256"
    check_blob(blobs, pin, label)
    idx_doc = json.loads((blobs / pin.split(":", 1)[1]).read_text())
    amd64 = [
        m for m in idx_doc.get("manifests", [])
        if m.get("platform", {}).get("os") == "linux"
        and m.get("platform", {}).get("architecture") == "amd64"
        and "vnd.docker.reference.type" not in (m.get("annotations") or {})
    ]
    if len(amd64) != 1:
        raise SystemExit(f"{label} index does not have one linux/amd64 manifest")
    verify_manifest_blobs(blobs, amd64[0]["digest"], label)

server_blobs = root / "images/ipso-server/blobs/sha256"
verify_manifest_blobs(server_blobs, digest, "ipso-server")
verify_sparse_layout(root / "images/postgres", pg_pin, "postgres")
verify_sparse_layout(root / "images/nginx", ngx_pin, "nginx")
PY
}

assert_archive() {
  local need
  for need in \
    manifest.sha256 \
    sbom/ipso-server.cdx.json \
    sbom/postgres.cdx.json \
    sbom/nginx.cdx.json \
    signatures/manifest.sigstore.json \
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
    deploy/bundle/.env.example \
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
  local dir=$1 base_name=$2 tar_in
  tar_in=$(mktemp)
  tar -C "$dir" -cf "$tar_in" .
  # kind mounts a tmpfs on /tmp inside the node, so docker cp to /tmp is not visible to exec.
  docker exec -i "${cluster}-control-plane" ctr -n k8s.io images import \
    --base-name "$base_name" --all-platforms --digests - <"$tar_in" >&2
  rm -f "$tar_in"
}

import_sparse_index() {
  local dir=$1 pin=$2 base_name=$3 index_ref=$4 tar_in listed
  tar_in=$(mktemp)
  python3 - "$dir" "$pin" "$tar_in" <<'PY'
import io, pathlib, sys, tarfile

root = pathlib.Path(sys.argv[1])
pin = sys.argv[2]
out_tar = pathlib.Path(sys.argv[3])
idx_bytes = (root / "blobs" / "sha256" / pin.split(":", 1)[1]).read_bytes()
with tarfile.open(out_tar, "w") as tar:
    tar.add(root / "oci-layout", arcname="oci-layout")
    info = tarfile.TarInfo("index.json")
    info.size = len(idx_bytes)
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(idx_bytes))
    for blob in sorted((root / "blobs" / "sha256").iterdir()):
        if blob.is_file():
            tar.add(blob, arcname=f"blobs/sha256/{blob.name}")
PY
  docker exec -i "${cluster}-control-plane" ctr -n k8s.io images import \
    --base-name "$base_name" --index-name "$index_ref" --platform linux/amd64 - <"$tar_in" >&2
  rm -f "$tar_in"
  listed=$(docker exec "${cluster}-control-plane" ctr -n k8s.io images ls)
  if ! awk -v want="$index_ref" -v d="$pin" '$1 == want && $3 == d { found = 1 } END { exit !found }' <<<"$listed"; then
    echo "kind did not store ${index_ref} with index digest ${pin}" >&2
    printf '%s\n' "$listed" >&2
    exit 1
  fi
}

tag_exact() {
  local src=$1 dest=$2 listed
  docker exec "${cluster}-control-plane" ctr -n k8s.io images tag "$src" "$dest" >/dev/null
  listed=$(docker exec "${cluster}-control-plane" ctr -n k8s.io images ls)
  if ! awk -v want="$dest" '$1 == want { found = 1 } END { exit !found }' <<<"$listed"; then
    echo "kind did not keep ${dest}" >&2
    printf '%s\n' "$listed" >&2
    exit 1
  fi
}

tag_digest() {
  local digest=$1 name=$2 listed src
  listed=$(docker exec "${cluster}-control-plane" ctr -n k8s.io images ls)
  if awk -v want="$name" '$1 == want { found = 1 } END { exit !found }' <<<"$listed"; then
    return
  fi
  src=$(awk -v d="$digest" '!found && $3 == d && $2 ~ /manifest/ && $2 !~ /index/ { found = $1 } END { if (found) print found }' <<<"$listed")
  if [[ -z "$src" ]]; then
    echo "kind has no runnable image for ${digest}" >&2
    printf '%s\n' "$listed" >&2
    exit 1
  fi
  tag_exact "$src" "$name"
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
  bounded 10m kubectl -n ipso rollout status statefulset/ipso-postgresql --timeout=10m
  bounded 10m kubectl -n ipso rollout status deploy/ipso-api --timeout=10m
  bounded 10m kubectl -n ipso rollout status deploy/ipso-worker --timeout=10m
  bounded 10m kubectl -n ipso rollout status deploy/ipso-front --timeout=10m
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
  phase "load images"
  import_layout "${extract}/images/ipso-server" "$server_repo"
  tag_digest "$server_digest" "${server_repo}@${server_digest}"
  import_sparse_index "${extract}/images/postgres" "$pg" "docker.io/library/postgres" "docker.io/library/postgres@${pg}"
  tag_exact "docker.io/library/postgres@${pg}" "postgres@${pg}"
  import_sparse_index "${extract}/images/nginx" "$ngx" "docker.io/nginxinc/nginx-unprivileged" "docker.io/nginxinc/nginx-unprivileged@${ngx}"
  tag_exact "docker.io/nginxinc/nginx-unprivileged@${ngx}" "nginxinc/nginx-unprivileged@${ngx}"

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
  phase "dex"
  bounded 5m kubectl -n ipso rollout status deploy/dex --timeout=300s

  phase "cut egress"
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
  phase "helm install"
  bounded 15m helm upgrade --install ipso "$chart" --namespace ipso \
    -f "${extract}/airgap-values.yaml" \
    -f "$ci_values" \
    --timeout 15m
  rm -f "$ci_values"
  wait_rollout
  wait_health
  refuse_foreign_image
}

prepare_stage() {
  mkdir -p "$stage/signatures" "$stage/sbom" "$stage/images" "$stage/chart" \
    "$stage/deploy/bundle" "$stage/deploy/compose"
}

start_registry() {
  phase "registry"
  mkdir -p "$out/zot"
  cat >"$out/zot-config.json" <<EOF
{
  "distSpecVersion": "1.1.1",
  "storage": {"rootDirectory": "${out}/zot"},
  "http": {"address": "127.0.0.1", "port": "5000"},
  "log": {"level": "info"}
}
EOF
  zot serve "$out/zot-config.json" >>"$out/zot.log" 2>&1 &
  zot_pid=$!
  wait_registry
}

stop_registry() {
  if [[ -n "${zot_pid}" ]] && kill -0 "$zot_pid" 2>/dev/null; then
    kill "$zot_pid" 2>/dev/null || true
    wait "$zot_pid" 2>/dev/null || true
  fi
  zot_pid=
}
pull_pinned() {
  prepare_stage
  # docker pull of an index digest fetches every architecture and does not finish in this job.
  # These archives live outside the staged tar and feed Syft only; the tar carries signed OCI layouts.
  phase "pull pinned images"
  bounded 5m crane pull --platform linux/amd64 --format tarball "postgres@${pg}" "${out}/postgres.tar"
  bounded 5m crane pull --platform linux/amd64 --format tarball "nginxinc/nginx-unprivileged@${ngx}" "${out}/nginx.tar"
}

push_saved_server() {
  phase "push server image"
  python3 - "${out}/server.tar" <<'PY'
import gzip, hashlib, json, pathlib, shutil, sys, tarfile, urllib.error, urllib.request

archive = pathlib.Path(sys.argv[1])
extract = archive.with_suffix("")
shutil.rmtree(extract, ignore_errors=True)
extract.mkdir(parents=True)
with tarfile.open(archive) as tar:
    root = extract.resolve()
    for member in tar.getmembers():
        target = (extract / member.name).resolve()
        if target != root and root not in target.parents:
            raise SystemExit(f"docker save path escapes the archive: {member.name}")
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not member.isfile():
            continue
        src = tar.extractfile(member)
        if src is None:
            raise SystemExit(f"docker save entry is empty: {member.name}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(src.read())
listed = json.loads((extract / "manifest.json").read_text())
if len(listed) != 1:
    raise SystemExit(f"docker save produced {len(listed)} images")
image = listed[0]
host = "http://127.0.0.1:5000"
base = f"{host}/v2/ipso-server"

def call(method, url, data=None, headers=None, ok=(200, 201, 202)):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = resp.read()
            if resp.status not in ok:
                raise SystemExit(f"{method} {url}: HTTP {resp.status} {body[:300]!r}")
            return resp.headers, body
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:500]
        raise SystemExit(f"{method} {url}: HTTP {exc.code} {detail}")

def upload(digest, data):
    headers, _ = call("POST", f"{base}/blobs/uploads/", b"", {"Content-Length": "0"})
    loc = headers.get("Location")
    if not loc:
        raise SystemExit(f"blob upload for {digest} returned no Location")
    if loc.startswith("/"):
        loc = host + loc
    sep = "&" if "?" in loc else "?"
    call(
        "PUT",
        f"{loc}{sep}digest={digest}",
        data,
        {"Content-Type": "application/octet-stream", "Content-Length": str(len(data))},
        ok=(201,),
    )

def blob(data, media):
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    upload(digest, data)
    return {"mediaType": media, "digest": digest, "size": len(data)}

config = (extract / image["Config"]).read_bytes()
diff_ids = json.loads(config).get("rootfs", {}).get("diff_ids", [])
if len(diff_ids) != len(image["Layers"]):
    raise SystemExit("layer count does not match image rootfs diff_ids")
layers = []
for name, want_diff in zip(image["Layers"], diff_ids):
    raw = (extract / name).read_bytes()
    if raw[:2] == b"\x1f\x8b":
        uncompressed = gzip.decompress(raw)
        compressed = raw
    else:
        uncompressed = raw
        compressed = gzip.compress(raw, mtime=0)
    got_diff = "sha256:" + hashlib.sha256(uncompressed).hexdigest()
    if got_diff != want_diff:
        raise SystemExit(f"layer {name} diff_id {got_diff} != {want_diff}")
    layers.append(blob(compressed, "application/vnd.oci.image.layer.v1.tar+gzip"))
manifest = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "config": blob(config, "application/vnd.oci.image.config.v1+json"),
    "layers": layers,
}
body = json.dumps(manifest, separators=(",", ":")).encode()
call(
    "PUT",
    f"{base}/manifests/airgap",
    body,
    {"Content-Type": manifest["mediaType"], "Content-Length": str(len(body))},
    ok=(201,),
)
print(f"pushed {len(layers)} layers", file=sys.stderr)
PY
}

build_and_push_server() {
  phase "build server image"
  bounded 8m docker build --provenance=false --sbom=false -t "${server_repo}:airgap" "$root"
  # Schema 2 conversion and BuildKit's registry export both held the job open
  # until it was cancelled. docker save is local. The manifest PUT is OCI, so
  # zot stores those bytes unchanged.
  phase "save server image"
  bounded 8m docker save -o "${out}/server.tar" "${server_repo}:airgap"
  push_saved_server
  server_digest=$(digest_of 127.0.0.1:5000/ipso-server:airgap)
  printf '%s\n' "$server_digest" >"$out/server.digest"
}

sign_and_tar() {
  server_digest=$(cat "$out/server.digest")
  if ! curl -fsS --max-time 5 \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    "http://127.0.0.1:5000/v2/ipso-server/manifests/${server_digest}" >/dev/null 2>&1; then
    push_saved_server
    require_same_digest "$(digest_of 127.0.0.1:5000/ipso-server:airgap)" "$server_digest" "ipso-server"
  fi
  publish_pinned "postgres@${pg}" 127.0.0.1:5000/postgres "$pg" postgres
  publish_pinned "nginxinc/nginx-unprivileged@${ngx}" 127.0.0.1:5000/nginx "$ngx" nginx

  phase "sbom and trusted root"
  write_sbom "docker-archive:${out}/server.tar" "${stage}/sbom/ipso-server.cdx.json"
  write_sbom "docker-archive:${out}/postgres.tar" "${stage}/sbom/postgres.cdx.json"
  write_sbom "docker-archive:${out}/nginx.tar" "${stage}/sbom/nginx.cdx.json"
  bounded 2m cosign trusted-root create --with-default-services --out "${stage}/trusted-root.json"
  cp "${stage}/trusted-root.json" "$out/trusted-root.json"

  sign_one 127.0.0.1:5000/ipso-server "$server_digest" ipso-server
  sign_ref 127.0.0.1:5000/postgres "$pg" postgres
  write_signed_layout "postgres@${pg}" 127.0.0.1:5000/postgres "$pg" "${stage}/images/postgres"
  sign_ref 127.0.0.1:5000/nginx "$ngx" nginx
  write_signed_layout "nginxinc/nginx-unprivileged@${ngx}" 127.0.0.1:5000/nginx "$ngx" "${stage}/images/nginx"

  helm package charts/ipso --destination "${stage}/chart"
  local chart
  chart=$(find "${stage}/chart" -name '*.tgz' -print -quit)
  bounded 2m cosign sign-blob --yes --bundle "${stage}/signatures/chart.sigstore.json" "$chart"

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
  rm -f "$env_file"
  if grep -q 'build:' <<<"$rendered"; then
    echo "rendered Compose still builds an image" >&2
    exit 1
  fi
  if ! grep -q "${server_repo}@${server_digest}" <<<"$rendered"; then
    echo "rendered Compose is missing the server digest" >&2
    exit 1
  fi

  python3 - "$stage" <<'PY'
import hashlib, pathlib, sys

stage = pathlib.Path(sys.argv[1]).resolve()
skip = {"manifest.sha256", "signatures/manifest.sigstore.json", "trusted-root.json"}
lines = []
for path in sorted(p for p in stage.rglob("*") if p.is_file()):
    rel = path.relative_to(stage).as_posix()
    if rel in skip:
        continue
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    lines.append(f"{h.hexdigest()}  {rel}")
(stage / "manifest.sha256").write_text("\n".join(lines) + "\n")
PY
  bounded 2m cosign sign-blob --yes \
    --bundle "${stage}/signatures/manifest.sigstore.json" \
    "${stage}/manifest.sha256"

  tar -C "$stage" -cf "$archive" .
  stop_registry
}

mode=${1:-all}
case "$mode" in
  all|pull|server|sign|verify|install) ;;
  *)
    echo "usage: $0 [all|pull|server|sign|verify|install]" >&2
    exit 1
    ;;
esac

require_tools "$mode"
require_pins
if [[ "$mode" == "all" || "$mode" == "pull" ]]; then
  rm -rf "$out"
fi
mkdir -p "$out"
trap cleanup EXIT
heartbeat &
heartbeat_pid=$!

wait_kind() {
  local waited=0 state
  while [[ -n "${kind_pid}" && -d "/proc/${kind_pid}" ]]; do
    state=$(cat "/proc/${kind_pid}/stat" 2>/dev/null || true)
    state=${state#*) }
    state=${state%% *}
    if [[ -z "$state" || "$state" == "Z" ]]; then
      break
    fi
    if (( waited >= 120 )); then
      echo "kind did not finish within 10 minutes" >&2
      exit 1
    fi
    sleep 5
    waited=$((waited + 1))
  done
  if ! wait "$kind_pid"; then
    echo "kind did not start" >&2
    exit 1
  fi
  kind_pid=
}

verified_server_digest() {
  python3 - "${extract}/images/ipso-server" <<'PY'
import json, pathlib, sys

layout = pathlib.Path(sys.argv[1])
idx = json.loads((layout / "index.json").read_text())
blobs = layout / "blobs" / "sha256"
found = []
for entry in idx.get("manifests") or []:
    dgst = entry.get("digest", "")
    if not dgst.startswith("sha256:"):
        continue
    blob_path = blobs / dgst.split(":", 1)[1]
    if not blob_path.is_file():
        continue
    doc = json.loads(blob_path.read_text())
    if "subject" in doc:
        continue
    if (doc.get("config") or {}).get("mediaType") == "application/vnd.oci.image.config.v1+json":
        found.append(dgst)
unique = sorted(set(found))
if len(unique) != 1:
    raise SystemExit(f"expected one verified ipso-server image manifest, got {len(unique)}")
print(unique[0])
PY
}

run_verify() {
  local home_dir root_file isolated_root layout_digest
  if [[ ! -r "$archive" || ! -f "$archive" ]]; then
    echo "airgap archive is not a readable file: $archive" >&2
    exit 1
  fi
  rm -f "$out/verified"
  root_file=$(trusted_root_path)
  extract_bootstrap "$archive" "$extract"
  home_dir=$(mktemp -d)
  isolated_root="${home_dir}/trusted-root.json"
  cp "$root_file" "$isolated_root"
  chmod 0644 "$isolated_root"
  phase "verify"
  verify_manifest_offline "$home_dir" "$isolated_root"
  extract_verified_archive "$archive" "$extract" "$root_file"
  verify_offline "$home_dir" "$isolated_root"
  rm -rf "$home_dir"
  assert_archive
  layout_digest=$(verified_server_digest)
  if [[ -f "$out/server.digest" ]]; then
    require_same_digest "$layout_digest" "$(cat "$out/server.digest")" "ipso-server"
  fi
  server_digest=$layout_digest
  check_pointers
  touch "$out/verified"
}

run_install() {
  if [[ ! -f "$out/verified" || ! -d "$extract/images" || "$archive" -nt "$out/verified" ]]; then
    run_verify
  else
    server_digest=$(verified_server_digest)
    if [[ -f "$out/server.digest" ]]; then
      require_same_digest "$server_digest" "$(cat "$out/server.digest")" "ipso-server"
    fi
    check_pointers
  fi
  phase "kind"
  python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
    kind create cluster --name "$cluster" --image "$kind_node" >"$out/kind.log" 2>&1 &
  kind_pid=$!
  wait_kind

  set -a
  # shellcheck disable=SC1091
  . ./.env.example
  set +a
  install_from_tar
  echo "air-gap tar ${archive}"
}

case "$mode" in
  all)
    pull_pinned
    start_registry
    build_and_push_server
    sign_and_tar
    run_verify
    run_install
    ;;
  pull)
    pull_pinned
    ;;
  server)
    start_registry
    build_and_push_server
    stop_registry
    ;;
  sign)
    start_registry
    sign_and_tar
    ;;
  verify)
    run_verify
    ;;
  install)
    run_install
    ;;
esac
