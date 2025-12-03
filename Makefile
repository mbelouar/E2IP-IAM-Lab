# Variables
PROJECT_NAME := secureauth
DOCKER_DIR := docker
COMPOSE_FILE := $(DOCKER_DIR)/docker-compose.yaml
PORT := 8000

# Build and run with Docker Compose in detached mode
up:
	cd $(DOCKER_DIR) && docker-compose up --build -d

# Stop Docker Compose services
down:
	cd $(DOCKER_DIR) && docker-compose down

# Rebuild everything (clean run)
rebuild: down up

# Show logs
logs:
	cd $(DOCKER_DIR) && docker-compose logs -f

# Remove containers, networks, and volumes
clean:
	cd $(DOCKER_DIR) && docker-compose down -v --rmi all 

# Execute bash in the web container
bash:
	cd $(DOCKER_DIR) && docker-compose exec web bash

# Local development commands
runserver:
	./venv/bin/python3 manage.py runserver 192.168.64.1:$(PORT)

runserver-ssl:
	@echo "Starting Django with SSL on https://secureauth.local:$(PORT)/"
	@echo "Note: You may see a browser warning about self-signed certificate - this is normal for development"
	@echo ""
	./venv/bin/python3 manage.py runserver_plus --cert-file ssl/cert.pem --key-file ssl/key.pem 192.168.64.1:$(PORT)

# Server management commands
stop-server:
	@echo "Stopping Django development server..."
	@pkill -f "manage.py runserver" || echo "No server running"
	@echo "Server stopped"

status:
	@echo "=== Django Server Status ==="
	@echo ""
	@if lsof -nP -iTCP:$(PORT) -sTCP:LISTEN 2>/dev/null | grep -q Python; then \
		echo "Status: 🟢 RUNNING"; \
		echo ""; \
		echo "Process Details:"; \
		lsof -nP -iTCP:$(PORT) -sTCP:LISTEN | grep Python || true; \
		echo ""; \
		echo "Access URLs:"; \
		echo "  - HTTPS: https://secureauth.local:$(PORT)/"; \
		echo "  - HTTP:  http://192.168.64.1:$(PORT)/"; \
	else \
		echo "Status: 🔴 NOT RUNNING"; \
		echo ""; \
		echo "To start the server, run:"; \
		echo "  make runserver-ssl  (HTTPS - recommended)"; \
		echo "  make runserver      (HTTP)"; \
	fi
	@echo ""

view-logs:
	@echo "Viewing server logs (Ctrl+C to exit)..."
	@echo ""
	@tail -f /tmp/django_ssl_server.log 2>/dev/null || tail -f /tmp/django_server.log 2>/dev/null || echo "No log file found"

# Build individual Docker images
build-linux:
	docker build -t $(PROJECT_NAME):linux -f $(DOCKER_DIR)/Dockerfile.linux .

build-windows:
	docker build -t $(PROJECT_NAME):windows -f $(DOCKER_DIR)/Dockerfile.windows .

# Legacy commands for backward compatibility
build: build-linux
run: up
stop: down
