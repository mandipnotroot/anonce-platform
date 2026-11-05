# SPDX-License-Identifier: AGPL-3.0-only
FROM node:24-bookworm-slim AS browser
WORKDIR /src
COPY package*.json ./
RUN npm ci
COPY web ./web
COPY scripts ./scripts
RUN npm run build

FROM golang:1.27-bookworm AS server
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/anonce ./cmd/anonce

FROM caddy:2.10.2 AS proxy
RUN chown -R 1000:1000 /data /config && setcap -r /usr/bin/caddy
USER 1000:1000

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=server /out/anonce /app/anonce
COPY --from=browser /src/web /app/web
ENV ANONCE_ADDR=:8080 ANONCE_WEB_DIR=/app/web
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/anonce"]
