#!/bin/sh

# This script is the entrypoint for the webapp container.
# It waits for the database to be available before starting the main application.

# The host and port for the database are passed as arguments
# We will get these from the docker-compose environment
DB_HOST="db"
DB_PORT="3306"

echo "Waiting for database at ${DB_HOST}:${DB_PORT}..."

# We use netcat (nc) to check if the port is open on the host.
# The `-z` flag makes nc scan for listening daemons, without sending any data.
while ! nc -z ${DB_HOST} ${DB_PORT}; do
  sleep 1 # wait for 1 second before trying again
done

echo "Database is up - starting application..."

# Execute the command passed to this script (the Gunicorn command from the Dockerfile)
exec "$@"