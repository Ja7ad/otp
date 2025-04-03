install-tools:
	go install mvdan.cc/gofumpt@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

unit_test:
	@echo "Running unit tests..."
	@go test ./...

race_test:
	@echo "Running race condition tests..."
	@go test ./... -race

fuzz_test:
	@echo "Running fuzzing tests..."
	@ go test -fuzz=FuzzDeriveOTP -fuzztime=30s

test: unit_test race_test fuzz_test

fmt:
	@echo "Formatting code..."
	gofumpt -l -w .

vet:
	@echo "Vetting code..."
	@go vet ./...

check: fmt vet

build-wasm-js:
	@echo "Running build wasm..."
	GOOS=js GOARCH=wasm go build -o otp-js/lib/otp.wasm ./wasm/main.go

.PHONY: test unit_test race_test fuzz_test
.PHONY: fmt vet check
.PHONY: build-wasm-js