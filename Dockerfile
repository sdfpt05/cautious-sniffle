# Multi-stage build for Data Privacy Vault
FROM python:3.10-slim as base

# Set working directory
WORKDIR /app

# Set Python environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install dependencies common to both services
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Install the package in development mode
RUN pip install -e .

# Create necessary directories
RUN mkdir -p data logs

# Set permissions
RUN chmod -R 755 /app

# CLI Service
FROM base as cli
ARG SERVICE=cli
ENV SERVICE=$SERVICE

# Additional CLI-specific setup
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Web Service
FROM base as web
ARG SERVICE=web
ENV SERVICE=$SERVICE

# Additional web-specific dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Expose the port (for the web service)
EXPOSE 5000

# Final image based on the SERVICE arg
FROM ${SERVICE}

# Set default command (will be overridden in docker-compose.yml)
CMD ["python", "-m", "data_vault_${SERVICE}.run"]