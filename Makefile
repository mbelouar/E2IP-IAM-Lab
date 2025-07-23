# Variables
PROJECT_NAME := secureauth
IMAGE_NAME := $(PROJECT_NAME)-image
CONTAINER_NAME := $(PROJECT_NAME)-container
PORT := 8000

# Build the Docker image
build:
	docker build -t $(IMAGE_NAME) .

# Run the container
run:
	docker run -d --name $(CONTAINER_NAME) -p $(PORT):8000 $(IMAGE_NAME)

# Stop and remove the container
stop:
	docker stop $(CONTAINER_NAME) || true
	docker rm $(CONTAINER_NAME) || true

# Rebuild everything (clean run)
rebuild: stop build run

# Show logs
logs:
	docker logs -f $(CONTAINER_NAME)

# Remove image, container, and volumes
clean: stop
	docker rmi $(IMAGE_NAME) || true
	docker volume prune -f

# Execute bash in container
bash:
	docker exec -it $(CONTAINER_NAME) bash
