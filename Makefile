# SPDX-License-Identifier: AGPL-3.0-only
.PHONY: fmt fmt-check test vet browser compose-check build
fmt:
	@bash -eu -o pipefail -c 'git ls-files -z -- "*.go" | xargs -0 -r gofmt -w'
fmt-check:
	@bash -eu -o pipefail -c 'files=$$(git ls-files -z -- "*.go" | xargs -0 -r gofmt -l); if [ -n "$$files" ]; then printf "Unformatted Go files:\n%s\n" "$$files"; exit 1; fi'
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
