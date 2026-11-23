{{- define "ipso.checks" -}}
{{- $_ := required "existingSecret is required" .Values.existingSecret -}}
{{- $_ := required "image.digest is required" .Values.image.digest -}}
{{- $_ := required "tenantID is required" .Values.tenantID -}}
{{- $_ := required "oidc.issuer is required" .Values.oidc.issuer -}}
{{- $_ := required "oidc.audience is required" .Values.oidc.audience -}}
{{- if .Values.telemetry.endpoint -}}
{{- if not (regexMatch "^https?://[^/\\s]+" .Values.telemetry.endpoint) -}}
{{- fail "telemetry.endpoint must be an http or https URL" -}}
{{- end -}}
{{- else if .Values.telemetry.namespace -}}
{{- fail "telemetry.namespace is set and telemetry.endpoint is not" -}}
{{- end -}}
{{- if .Values.bootstrap.enabled -}}
{{- $_ := required "bootstrap.tenantName is required" .Values.bootstrap.tenantName -}}
{{- $_ := required "bootstrap.person is required" .Values.bootstrap.person -}}
{{- $_ := required "bootstrap.personName is required" .Values.bootstrap.personName -}}
{{- $_ := required "bootstrap.subject is required" .Values.bootstrap.subject -}}
{{- $_ := required "bootstrap.kekSecret is required" .Values.bootstrap.kekSecret -}}
{{- end -}}
{{- end -}}

{{/* The one variable that turns telemetry on in the api and the worker (ADR-0155). */}}
{{- define "ipso.telemetryEnv" -}}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ .Values.telemetry.endpoint | quote }}
{{- end -}}

{{/* Egress to the Collector of the cluster, for the policy of the api and of the worker. */}}
{{- define "ipso.telemetryEgress" -}}
- to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: {{ .Values.telemetry.namespace | quote }}
      podSelector: {}
  ports:
    - protocol: TCP
      port: {{ .Values.telemetry.port }}
{{- end -}}

{{- define "ipso.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "ipso.ref" -}}
{{- $digest := required (printf "%s is required" .label) .digest -}}
{{- if not (hasPrefix "sha256:" $digest) -}}
{{- fail (printf "%s must start with sha256:" .label) -}}
{{- end -}}
{{- printf "%s@%s" .repository $digest -}}
{{- end -}}

{{- define "ipso.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "ipso.selector" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "ipso.appEnv" -}}
- name: IPSO_DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.existingSecret }}
      key: database-url
- name: IPSO_TENANT_ID
  value: {{ .Values.tenantID | quote }}
{{- end -}}

{{- define "ipso.nginx" }}
worker_processes auto;
pid /tmp/nginx.pid;
error_log /dev/stderr warn;

events {
    worker_connections 1024;
}

http {
    access_log off;
    server_tokens off;
    client_body_temp_path /tmp/client_temp;
    proxy_temp_path /tmp/proxy_temp;
    fastcgi_temp_path /tmp/fastcgi_temp;
    uwsgi_temp_path /tmp/uwsgi_temp;
    scgi_temp_path /tmp/scgi_temp;
    client_max_body_size 1m;

    limit_req_zone $binary_remote_addr zone=per_client:10m rate=20r/s;
    limit_req_status 429;

    upstream ipso_api {
        server {{ include "ipso.fullname" . }}-api:8080;
    }

    server {
        listen 8080;
{{- if .Values.front.tls.enabled }}
        add_header Strict-Transport-Security "max-age=31536000" always;
{{- end }}

        error_page 429 = @rate_limited;
        location @rate_limited {
            default_type application/json;
            return 429 '{"error":"rate_limited"}';
        }

        location = /nginx-health {
            access_log off;
            default_type text/plain;
            return 204;
        }

        location / {
            limit_req zone=per_client burst=40 nodelay;
            proxy_pass http://ipso_api;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $host;
            proxy_connect_timeout 3s;
            proxy_read_timeout 15s;
            proxy_max_temp_file_size 0;
        }
    }
}
{{- end }}
