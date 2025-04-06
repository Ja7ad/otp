install-tools:
	go install mvdan.cc/gofumpt@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

unit_test:
	@echo "Running unit tests..."
	@go test ./... -v

race_test:
	@echo "Running race condition tests..."
	@go test ./... -race -v

fuzz_test:
	@echo "Running fuzzing tests..."
	@ go test -fuzz=FuzzDeriveRFC4226 -fuzztime=30s
	@ go test -fuzz=FuzzDeriveRFC6287 -fuzztime=30s

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

gen-swagger:
	@echo "Generate swagger..."
	@cd internal/app && swag init -g api/handlers.go && swag fmt

.PHONY: test unit_test race_test fuzz_test
.PHONY: fmt vet check
.PHONY: build-wasm-js