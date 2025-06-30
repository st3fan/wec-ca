# WEC CA Makefile

# Variables
IMAGE_NAME := wec-ca
IMAGE_TAG := latest
REGISTRY := 
FULL_IMAGE := $(if $(REGISTRY),$(REGISTRY)/,)$(IMAGE_NAME):$(IMAGE_TAG)

# Default target
.PHONY: help
help: ## Show this help message
	@echo "WEC CA Build Targets:"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

# Development targets
.PHONY: build
build: ## Build the Go application locally
	go build -o wec-ca .

.PHONY: test
test: ## Run tests
	go test -v ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

.PHONY: clean
clean: ## Clean build artifacts
	rm -f wec-ca coverage.out coverage.html

# Docker targets
.PHONY: docker-build
docker-build: ## Build Docker image
	docker build -t $(FULL_IMAGE) .

.PHONY: docker-build-no-cache
docker-build-no-cache: ## Build Docker image without cache
	docker build --no-cache -t $(FULL_IMAGE) .

.PHONY: docker-run
docker-run: ## Run Docker container locally
	docker run --rm -p 8443:8443 \
		-e WECCA_HOSTNAME=localhost \
		-e WECCA_DOMAIN=localhost \
		-e WECCA_SERVER_URL=https://localhost:8443 \
		$(FULL_IMAGE)

.PHONY: docker-run-detached
docker-run-detached: ## Run Docker container in background
	docker run -d --name wec-ca \
		-p 8443:8443 \
		-v wec-ca-data:/data \
		-e WECCA_HOSTNAME=localhost \
		-e WECCA_DOMAIN=localhost \
		-e WECCA_SERVER_URL=https://localhost:8443 \
		$(FULL_IMAGE)

.PHONY: docker-stop
docker-stop: ## Stop and remove Docker container
	docker stop wec-ca || true
	docker rm wec-ca || true

.PHONY: docker-logs
docker-logs: ## Show Docker container logs
	docker logs -f wec-ca

.PHONY: docker-shell
docker-shell: ## Get shell access to running container (for debugging)
	docker exec -it wec-ca sh

# Docker Compose targets
.PHONY: compose-up
compose-up: ## Start services with docker-compose
	docker-compose up -d

.PHONY: compose-down
compose-down: ## Stop services with docker-compose
	docker-compose down

.PHONY: compose-logs
compose-logs: ## Show docker-compose logs
	docker-compose logs -f

.PHONY: compose-build
compose-build: ## Build docker-compose services
	docker-compose build

.PHONY: compose-prod-up
compose-prod-up: ## Start production services
	docker-compose -f docker-compose.prod.yml up -d

.PHONY: compose-prod-down
compose-prod-down: ## Stop production services
	docker-compose -f docker-compose.prod.yml down

# Utility targets
.PHONY: docker-size
docker-size: ## Show Docker image size
	docker images $(IMAGE_NAME) --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

.PHONY: docker-inspect
docker-inspect: ## Inspect Docker image
	docker inspect $(FULL_IMAGE)

.PHONY: test-acme
test-acme: ## Test ACME endpoint (requires running server)
	curl -k https://localhost:8443/acme/directory | jq .

.PHONY: check-health
check-health: ## Check container health
	docker-compose ps

# Development workflow
.PHONY: dev
dev: build test ## Run development workflow (build + test)

.PHONY: docker-dev
docker-dev: docker-build docker-run ## Run Docker development workflow

.PHONY: all
all: test docker-build ## Run all checks and build Docker image