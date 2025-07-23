#!/bin/bash
set -e

# This script's only job is to execute whatever command it is given.
# The PATH and environment are inherited directly from the Docker build.
echo "Entrypoint executing command: $@"
exec "$@"