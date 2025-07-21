# Dockerfile (Final Version with Disk Space Fix)

# Start from a specific, stable Debian version for better package compatibility
FROM python:3.11-slim-bookworm

# Set the working directory
WORKDIR /app

# Add Python's bin and local bin directories to the system's PATH.
# This ensures that any command run in the container can find executables
# installed by pip (like gunicorn) and the correct python interpreter.
ENV PATH=/root/.local/bin:$PATH

# --- Stage 1: Install System Dependencies ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    netcat-openbsd \
    git \
    ca-certificates \
    curl \
    libmagic1 \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# --- Stage 2: Add Docker's official GPG key and set up the repository ---
RUN install -m 0755 -d /etc/apt/keyrings
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
RUN chmod a+r /etc/apt/keyrings/docker.gpg
RUN echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null
RUN apt-get update

# --- Stage 3: Install the Docker CLI client ---
RUN apt-get install -y docker-ce-cli

# --- Stage 4: Install Python dependencies (OPTIMIZED FOR SIZE) ---
COPY requirements.txt .
RUN \
    # Install the smaller, CPU-only version of torch first
    pip install --no-cache-dir torch==2.7.1 --index-url https://download.pytorch.org/whl/cpu && \
    \
    # Now, install all other requirements from the file, skipping torch if it's re-listed
    pip install --no-cache-dir -r requirements.txt


# --- Stage 3: Copy application code ---
COPY . .



# --- Stage 5: Copy application and set up entrypoint ---
COPY . .
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
# Copy the new gunicorn config file into the container
COPY gunicorn.conf.py .

# The CMD is now much cleaner. It just tells gunicorn to use our config file.
# We no longer need --preload, --timeout, or --log-level here.
CMD ["gunicorn", "-c", "gunicorn.conf.py", "asgi:app"]