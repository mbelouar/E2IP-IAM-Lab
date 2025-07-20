# Django SAML2 Auth App Makefile
# Helper commands for development and deployment

.PHONY: setup run migrate collectstatic test clean docker-build docker-run

# Variables
PYTHON = python
PIP = pip
MANAGE = $(PYTHON) manage.py
DOCKER = docker
DOCKER_COMPOSE = docker-compose

# Default target
all: setup

# Setup the project
setup:
	@echo "Setting up the project..."
	$(PIP) install -r requirements.txt
	$(PYTHON) download_metadata.py
	$(MANAGE) migrate
	$(MANAGE) collectstatic --noinput
	@echo "Setup complete. Run 'make run' to start the server."

# Run development server
run:
	@echo "Starting development server..."
	$(MANAGE) runserver

# Run migrations
migrate:
	@echo "Running migrations..."
	$(MANAGE) migrate

# Create a test admin user
create-admin:
	@echo "Creating test admin user..."
	$(MANAGE) create_test_admin

# Collect static files
collectstatic:
	@echo "Collecting static files..."
	$(MANAGE) collectstatic --noinput

# Run tests
test:
	@echo "Running tests..."
	$(MANAGE) test
	$(PYTHON) test_saml_config.py

# Clean up temporary files
clean:
	@echo "Cleaning up..."
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name "*.egg" -exec rm -rf {} +
	find . -type d -name ".coverage" -exec rm -rf {} +
	find . -type d -name "htmlcov" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".tox" -exec rm -rf {} +
	find . -type f -name ".coverage" -delete
	find . -type f -name "coverage.xml" -delete

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	$(DOCKER) build -t adfs-auth-app .

# Run with Docker Compose
docker-run:
	@echo "Starting containers with Docker Compose..."
	$(DOCKER_COMPOSE) up -d

# Stop Docker containers
docker-stop:
	@echo "Stopping Docker containers..."
	$(DOCKER_COMPOSE) down

# Show help
help:
	@echo "Available targets:"
	@echo "  setup          - Install dependencies and initialize the project"
	@echo "  run            - Run development server"
	@echo "  migrate        - Apply database migrations"
	@echo "  create-admin   - Create a test admin user"
	@echo "  collectstatic  - Collect static files"
	@echo "  test           - Run tests"
	@echo "  clean          - Clean up temporary files"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Start containers with Docker Compose"
	@echo "  docker-stop    - Stop Docker containers"
	@echo "  help           - Show this help message"
