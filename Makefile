# SPDX-License-Identifier: AGPL-3.0-only
.PHONY: test vet browser compose-check build
test:
	go test -race ./...
vet:
	go vet ./...
browser:
	npm ci
	npm run build
	npm test
	npm run test:interop
compose-check:
	docker compose config --quiet
build:
	docker compose build
