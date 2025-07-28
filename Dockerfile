# Dockerfile (Multi-Stage)

# --- Stage 1: The 'base' stage with common setup ---
FROM python:3.11-slim AS base
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

# --- Stage 2: The 'production' stage (CPU-only, for CI/Deployment) ---
FROM base AS production
# Install only minimal system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Install the lightweight CPU-only requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "-c", "gunicorn.conf.py", "asgi:app"]

# --- Stage 3: The 'dev-gpu' stage (for local GPU development) ---
FROM base AS dev-gpu
# Install build tools and CUDA repository
RUN apt-get update && apt-get install -y --no-install-recommends \
    gnupg wget build-essential \
    && rm -rf /var/lib/apt/lists/*
RUN wget https://developer.download.nvidia.com/compute/cuda/repos/debian11/x86_64/cuda-keyring_1.0-1_all.deb && \
    dpkg -i cuda-keyring_1.0-1_all.deb && \
    apt-get update

# Install the full GPU requirements
COPY requirements-dev-gpu.txt .
RUN pip install --no-cache-dir -r requirements-dev-gpu.txt

COPY . .
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "-c", "gunicorn.conf.py", "asgi:app"]