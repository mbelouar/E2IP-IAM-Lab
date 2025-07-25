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
	./venv/bin/python3 manage.py runserver 0.0.0.0:$(PORT)

runserver-ssl:
	./venv/bin/python3 manage.py runserver_plus --cert-file ssl/cert.pem --key-file ssl/key.pem 0.0.0.0:$(PORT)

# Build individual Docker images
build-linux:
	docker build -t $(PROJECT_NAME):linux -f $(DOCKER_DIR)/Dockerfile.linux .

build-windows:
	docker build -t $(PROJECT_NAME):windows -f $(DOCKER_DIR)/Dockerfile.windows .

# Legacy commands for backward compatibility
build: build-linux
run: up-d
stop: down
