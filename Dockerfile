# SPDX-License-Identifier: AGPL-3.0-only
FROM node:26.12.1-alpine3.24 AS browser
WORKDIR /src
COPY package*.json ./
RUN npm ci
COPY web ./web
COPY scripts ./scripts
RUN npm run build

FROM golang:1.27.3-alpine3.23 AS server
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/anonce ./cmd/anonce

FROM caddy:2.11.8-alpine AS proxy
RUN chown -R 1000:1000 /data /config && setcap -r /usr/bin/caddy
USER 1000:1000

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=server /out/anonce /app/anonce
COPY --from=browser /src/web /app/web
ENV ANONCE_ADDR=:8080 ANONCE_WEB_DIR=/app/web
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/anonce"]
