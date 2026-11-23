#!/usr/bin/env python3
"""Checks a rendered chart. The manifest is untrusted YAML split on document markers."""

import sys


def documents(text):
    parts = text.split("\n---\n")
    return [part.strip() for part in parts if part.strip() and part.strip() != "---"]


def component(doc):
    # The first component label is the object's own. A policy also names other components later.
    for line in doc.splitlines():
        stripped = line.strip()
        if stripped.startswith("app.kubernetes.io/component:"):
            return stripped.split(":", 1)[1].strip()
    return ""


def main():
    path = sys.argv[1]
    want_bootstrap = "--bootstrap" in sys.argv[2:]
    want_telemetry = "--telemetry" in sys.argv[2:]
    docs = documents(open(path, encoding="utf-8").read())
    if not docs:
        sys.exit("the render is empty")

    images = []
    saw_policy = False
    migrate_env = False
    api_migrate_env = False
    bootstrap = False
    bootstrap_kek = False
    telemetry_env = set()
    telemetry_policy = set()
    for doc in docs:
        if "\nkind: Secret\n" in f"\n{doc}\n" or doc.startswith("kind: Secret\n"):
            sys.exit("the render contains a Secret")
        if "type: LoadBalancer" in doc or "type: NodePort" in doc:
            sys.exit("the render publishes a Service beyond ClusterIP")
        for line in doc.splitlines():
            if line.strip().startswith("image:"):
                images.append(line.strip())
        kind = ""
        for line in doc.splitlines():
            if line.strip().startswith("kind:"):
                kind = line.strip().split(":", 1)[1].strip()
                break
        if kind == "NetworkPolicy" and component(doc) in {"api", "worker"}:
            saw_policy = True
            if "169.254.0.0/16" not in doc or "10.0.0.0/8" not in doc:
                sys.exit("the api or worker policy is missing the public-address exceptions")
        elif kind == "NetworkPolicy":
            saw_policy = True
        name = component(doc)
        # Telemetry is for the api and the worker (ADR-0155). No Job and no front holds the variable.
        if "OTEL_" in doc:
            if kind != "Deployment" or name not in {"api", "worker"}:
                sys.exit(f"telemetry settings reached a {kind} of {name}")
            telemetry_env.add(name)
        if kind == "NetworkPolicy" and name in {"api", "worker"} and "port: 4318" in doc:
            if 'kubernetes.io/metadata.name: "observability"' not in doc:
                sys.exit(f"the {name} policy opens the collector port to more than its namespace")
            telemetry_policy.add(name)
        if name == "migrate" and "IPSO_MIGRATE_DATABASE_URL" in doc:
            migrate_env = True
        if name == "api" and "IPSO_MIGRATE_DATABASE_URL" in doc:
            api_migrate_env = True
        if name == "worker" and "IPSO_MIGRATE_DATABASE_URL" in doc:
            sys.exit("the worker holds the migration credential")
        if name == "bootstrap":
            bootstrap = True
            if "IPSO_TENANT_KEK" in doc:
                bootstrap_kek = True

    if not images:
        sys.exit("the render has no image")
    for image in images:
        if "@sha256:" not in image:
            sys.exit(f"image is not a digest: {image}")
    if not saw_policy:
        sys.exit("the render has no NetworkPolicy")
    if not migrate_env:
        sys.exit("the migrate Job has no migration URL")
    if api_migrate_env:
        sys.exit("the api holds the migration credential")
    if want_bootstrap:
        if not bootstrap or not bootstrap_kek:
            sys.exit("bootstrap is enabled but the Job does not mount the key encryption key")
    elif bootstrap:
        sys.exit("bootstrap is in the default render")
    if want_telemetry:
        if telemetry_env != {"api", "worker"} or telemetry_policy != {"api", "worker"}:
            sys.exit(f"telemetry is on and the api and the worker do not both have the endpoint and the egress: {sorted(telemetry_env)} {sorted(telemetry_policy)}")
    elif telemetry_env or telemetry_policy:
        sys.exit("telemetry is in the default render")
    print(f"checked {len(docs)} documents, {len(images)} images")


if __name__ == "__main__":
    main()
