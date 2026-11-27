# Telemetry

`ipso-server` can send OpenTelemetry traces and metrics over OTLP/HTTP ([ADR-0155](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0155-opentelemetry-over-otlp-with-an-attribute-allowlist.md)). It sends nothing until an operator sets one variable, so an install that is not told where to send telemetry sends none.

## Turn it on

Set `OTEL_EXPORTER_OTLP_ENDPOINT` on the process, for example `http://otel-collector:4318`. The four long-running roles read it: `--role=api`, `--role=worker`, `webhooks` and `runtasks`. A one-shot command (`migrate`, `tenant`, `probe`, `audit-log`) sends nothing. `OTEL_SDK_DISABLED=true` keeps telemetry off even when the endpoint is set.

The standard variables of the SDK work as usual: `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TIMEOUT` and the certificate variables, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_TRACES_SAMPLER` and its argument, `OTEL_BSP_*`, and `OTEL_METRIC_EXPORT_INTERVAL` (60 seconds by default). Only OTLP over HTTP with protobuf is built in. A process that is told `OTEL_EXPORTER_OTLP_PROTOCOL=grpc`, any `OTEL_TRACES_EXPORTER` or `OTEL_METRICS_EXPORTER` other than `otlp`, an endpoint that is not an http or https URL, or a header list that is not `name=value` pairs with percent-encoded values, refuses to start and says which variable, never its value. The logger of the SDK, which prints the input that failed to parse, is replaced by one that says one fixed line a minute, so a token in a header cannot reach a log.

The Helm chart has one value for it, `telemetry.endpoint`, which goes to the api and the worker. When the receiver is a Collector in the cluster, `telemetry.namespace` and `telemetry.port` open the egress of both pods to that namespace and port. For a public receiver use https on port 443: the policy of the api opens no other public port, and the policy of the worker opens 80 as well. The chart holds no header and no secret: the Collector authenticates to its backend. The webhooks and run task services are not in the chart.

A failing export is logged once a minute, without the endpoint, and never stops a request or a job.

## What is sent

Each role is one service: `ipso-api`, `ipso-worker`, `ipso-webhooks` and `ipso-runtasks`, in the namespace `ipso`, with its version. The resource has no host name, no process owner and no command line.

| Signal | Name | Meaning |
| --- | --- | --- |
| Metric | `http.server.request.duration` (s) | One point for each request, except `/healthz` |
| Metric | `ipso.job.duration` (s) | From the moment a job was due to its end, so the wait in a queue counts. With kind `check` it is the time from a delivery to its check result |
| Metric | `mcp.server.operation.duration` (s) | One point for each MCP operation that reaches the server |
| Span | `METHOD route` | One for each request. Every request starts a trace of its own |
| Span | `job kind` | One for each River job, webhook job and run task job |
| Span | `tools/call tool` | One for each MCP operation |

Prometheus names the metrics `http_server_request_duration_seconds`, `ipso_job_duration_seconds` and `mcp_server_operation_duration_seconds`, each with `_bucket`, `_count` and `_sum`. The buckets include the thresholds of section 15 of the specification: 0.4 s and 0.5 s, and 60 s and 300 s. Exemplars are on, so a point of a histogram can name the trace it came from.

## The attributes

A span or a metric point carries these keys and no others.

| Key | Values |
| --- | --- |
| `http.request.method` | A standard method, or `_OTHER` |
| `http.route` | The pattern the mux matched, such as `/v1/decisions/{ref}`. Never the path |
| `http.response.status_code` | The status |
| `error.type` | The status for a 5xx, `panic`, or `rpc_error` |
| `ipso.tenant.id` | The tenant. On every point of a role that has one, and on each webhook delivery once its installation is mapped. `runtasks` has none |
| `ipso.job.kind` | A constant of the code: `check`, `merged_pr`, `advisory_pr`, `runtask`, or a River job kind |
| `ipso.job.outcome` | `ok`, `error`, `timeout`, `canceled` or `panic` |
| `mcp.method.name` | A method of the MCP server, or `_OTHER` |
| `gen_ai.tool.name` | One of the four tools of the MCP server, and only on `tools/call` |

## What is never sent

Telemetry never holds a path, a query string, a header, a client address, a user agent, a request or response body, the text of an error, a name, a login, an email, a repository, a token or a person of any kind. The tenant id is the only identifier. No dimension names a person ([ADR-0012](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0012-no-per-person-metrics.md)).

The code that records a point passes bounded values, and two more layers hold if a later change records something else. A metric view keeps only the keys above. The exporters drop every other span attribute, every span event and link, the text of a span status, and the attributes of an exemplar. A `traceparent` header from a caller is ignored, and nothing is propagated to GitHub, a model provider or HCP Terraform.

`ci / telemetry` sends a request with an email in its path, a name in its query, a user agent and a bearer token, and fails when any of them reaches a series, an exemplar or a trace. It uploads the series and the spans it read as the artifact `telemetry-sample`, which is what a person reads when reviewing a release for personal data.

## Logs

Logs stay JSON on stderr, as before. A line written with the context of a request or a job also carries `trace_id` and `span_id`, so a log and its trace can be joined. Collect them with the log agent of the platform or the filelog receiver of the Collector. They are not sent over OTLP.

## Dashboards

`deploy/telemetry/dashboards` has one Grafana dashboard for each role: `ipso-api`, `ipso-worker`, `ipso-webhooks` and `ipso-runtasks`. Import them into any Grafana that reads the metrics. Each has a data source variable and, except the run task dashboard, a tenant variable. They select a role by the `job` label, `ipso/ipso-api` and so on, which is how Prometheus names a service from its namespace and its name.

The panels show the rate, the errors and the p50, p95 and p99 latency by route, status, job kind and outcome. The dashboards of the api and the webhooks service also show the indicators of section 15: the share of answers that are not a server error, the p95 of `decisions.applicable`, and the share of check results within 60 seconds. The objectives and the alerts on them are written in the SLO policy, not here.

A dot on a latency panel is an exemplar. To follow it to the trace, set `exemplarTraceIdDestinations` of the Prometheus data source to the Tempo data source.

## Try it on a laptop

```sh
cp .env.example .env
docker compose -f compose.yaml -f deploy/telemetry/compose.yaml up --build
```

The overlay adds one container with a Collector, Prometheus, Tempo, Loki and Grafana, and points the api and the worker at it with a metric interval of 5 seconds. Grafana is at `http://127.0.0.1:3000`, user `admin`, password `admin`, and the dashboards are in the folder `ipso`. Every port is on the loopback address and the data is in memory. The overlay is a tool for development and for the test below: it is not in the chart or in the air-gapped bundle.

## Tests

`go test ./...` checks that every dashboard query uses only metrics the code sends and labels from the list above, and that no label could name a person. With the overlay running, this runs the whole path:

```sh
set -a; . ./.env.example; set +a
IPSO_TELEMETRY_STACK=1 go test -tags telemetry -count=1 -v ./deploy/telemetry
```

It reads the series of the api and the worker of the stack from Prometheus, an exemplar of each role and its trace from Tempo, and the four dashboards from Grafana, and runs every query of every panel. The stack runs no webhooks service and no run task service, so the test sends their telemetry through the same package. Without `IPSO_TELEMETRY_STACK` it does that for all four roles.

## Not covered

There are no spans for database calls or for calls to GitHub, a model or HCP Terraform. The job of a run task starts a trace of its own, because the receiver does not hand the request to the queue. The data plane gateway of the enterprise build is not instrumented.
