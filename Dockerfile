# Dockerfile (Back to Basics, Final Version)

# Start from a clean, official Python image. This is more stable.
FROM python:3.11-slim

# Set environment variables to prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1

# Install essential system dependencies. We need wget and gnupg to add the NVIDIA repo.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gnupg \
    wget \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# --- Add NVIDIA's CUDA repository to get the necessary drivers ---
# This is the official method recommended by NVIDIA for non-NVIDIA base images.
RUN wget https://developer.download.nvidia.com/compute/cuda/repos/debian11/x86_64/cuda-keyring_1.0-1_all.deb && \
    dpkg -i cuda-keyring_1.0-1_all.deb && \
    apt-get update

# Install the specific CUDA toolkit version required by PyTorch
#RUN apt-get install -y cuda-toolkit-12-1 && \
    #rm -rf /var/lib/apt/lists/*

# Set PATH to include CUDA binaries
ENV PATH /usr/local/cuda-12.1/bin:${PATH}
ENV LD_LIBRARY_PATH /usr/local/cuda-12.1/lib64:${LD_LIBRARY_PATH}

# Set the working directory
WORKDIR /app

# Copy requirements file first for caching
COPY requirements.txt .

# Install Python packages.
RUN pip install --no-cache-dir -r requirements.txt

# --- Verification Step ---
# Let's see if this simpler environment works.
RUN python -c "import torch; print(f'Torch {torch.__version__} import verification successful!')"

# Copy the rest of the application
COPY . .

# Your entrypoint and cmd are fine
RUN chmod +x /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "-c", "gunicorn.conf.py", "asgi:app"]