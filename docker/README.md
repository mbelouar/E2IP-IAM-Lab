# Docker Configuration

This folder contains all Docker-related files for the E2IP IAM Lab project.

## Files

- `Dockerfile.linux` - Docker configuration for Linux platforms (amd64, arm64)
- `Dockerfile.windows` - Docker configuration for Windows platform
- `docker-compose.yaml` - Docker Compose configuration for local development

## Quick Start

### Using Makefile Commands (Recommended)

From the project root directory, use these convenient commands:

#### Development Commands

```bash
# Start the application (foreground, with logs)
make up

# Start the application in background
make up-d

# Stop the application
make down

# Restart everything (clean restart)
make rebuild

# View application logs
make logs

# Access container shell for debugging
make bash
```

#### Maintenance Commands

```bash
# Clean up containers, networks, and volumes
make clean

# Build individual platform images
make build-linux    # Linux image
make build-windows  # Windows image
```

#### Legacy Commands (for backward compatibility)

```bash
make build    # Same as build-linux
make run      # Same as up-d
make stop     # Same as down
```

### Manual Docker Commands

If you prefer not to use the Makefile:

#### Using Docker Compose

```bash
# From the project root directory:
cd docker
docker-compose up --build                    # Start (foreground)
docker-compose up --build -d                 # Start (background)
docker-compose down                          # Stop
docker-compose logs -f                       # View logs
docker-compose exec web bash                 # Shell access
```

#### Building individual images

```bash
# From the project root directory:
docker build -t secureauth:linux -f docker/Dockerfile.linux .
docker build -t secureauth:windows -f docker/Dockerfile.windows .
```

#### Running the containers

```bash
docker run -p 8000:8000 secureauth:linux
docker run -p 8000:8000 secureauth:windows
```

## Accessing the Application

The application will be available at `http://localhost:8000`

## CI/CD Integration

The GitHub Actions workflow automatically builds and pushes multi-platform images to Docker Hub using these Dockerfiles.

## Development Notes

- **Build Context**: Both Dockerfiles use the project root as build context (`.`) with paths relative to the project root
- **Cross-Platform Compatibility**: Path syntax is normalized for both Linux and Windows Docker builds
- **Volume Mounts**: Docker Compose is configured to mount the project directory for development hot-reloading
- **Environment**: Environment variables are loaded from the `.env` file in the project root
- **Database**: SQLite database files are excluded from Docker images via `.dockerignore`
- **Hot Reload**: Changes to Python files will automatically restart the Django development server
