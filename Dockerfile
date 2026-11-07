# The ipso-server image. Every stage is pinned by digest. The binary is static and embeds the web app, so the
# runtime image holds nothing but the binary and the CA bundle, and runs as a non-root user.

# The web app (ADR-0106). npm runs no install script (web/.npmrc), so the build is the only code that runs, and
# only its output goes on: Vite writes the app to internal/webapp/dist/app.
FROM node:24.22.2-bookworm-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json web/.npmrc ./
RUN npm ci
COPY web ./
RUN npm run build

FROM golang:1.27.1@sha256:162be5298a40ed317005c8339c6de4d10d3eef336d66dc8e9259b03ab9d3a6d2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY --from=web /src/internal/webapp/dist/app ./internal/webapp/dist/app
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/ipsofacto-io/ipso-server/internal/cli.Version=${VERSION}" \
    -o /out/ipso-server ./cmd/ipso-server

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/ipso-server /usr/local/bin/ipso-server
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/ipso-server"]
