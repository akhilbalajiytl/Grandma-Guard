# Dockerfile (GPU Enabled, Streamlined)

# Start from a specific, stable Debian version
FROM python:3.11-slim-bookworm

# Set the working directory
WORKDIR /app

# Prevent Python from writing .pyc files to avoid cache issues
ENV PYTHONDONTWRITEBYTECODE=1

# Add Python's bin and local bin directories to the system's PATH.
ENV PATH=/root/.local/bin:$PATH

# --- Stage 1: Install System Dependencies ---
# We only need the essentials for building Python packages.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# --- Stage 2: Install Python dependencies (GPU ENABLED) ---
COPY requirements.txt .
# This relies on your requirements.txt being updated to specify the CUDA torch version
RUN pip install --no-cache-dir -r requirements.txt

# --- Stage 3: Add a diagnostic command ---
# This will run during the build to confirm if the NVIDIA driver is visible.
RUN nvidia-smi || echo "nvidia-smi check failed, continuing with CPU..."

# --- Stage 4: Copy application and set up entrypoint ---
COPY . .
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "-c", "gunicorn.conf.py", "asgi:app"]