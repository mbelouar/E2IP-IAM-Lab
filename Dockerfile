FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libxml2-dev \
    libxmlsec1-dev \
    libxmlsec1-openssl \
    pkg-config \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Generate self-signed certificates if they don't exist
RUN if [ ! -f /app/saml/certs/sp.key ]; then \
    mkdir -p /app/saml/certs && \
    openssl req -new -x509 -days 3650 -nodes -out /app/saml/certs/sp.crt -keyout /app/saml/certs/sp.key -subj "/CN=auth_app.example.com"; \
    fi

# Download metadata
RUN python download_metadata.py

# Run migrations
RUN python manage.py migrate

# Collect static files
RUN python manage.py collectstatic --noinput

# Expose port
EXPOSE 8000

# Run the application
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "auth_app.wsgi:application"]
