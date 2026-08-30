.PHONY: consumer-smoke format format-check test tidy-check verify

consumer-smoke:
	./scripts/verify-consumer.sh

format:
	gofmt -w $$(find . -name '*.go' -not -path './.git/*')

format-check:
	test -z "$$(gofmt -l .)"

test:
	go test -race -coverprofile=coverage.out ./...

tidy-check:
	go mod tidy
	git diff --exit-code -- go.mod go.sum

verify: format-check tidy-check
	go vet ./...
	go test -race -coverprofile=coverage.out ./...
