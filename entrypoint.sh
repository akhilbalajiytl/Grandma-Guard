#!/bin/bash
# A "smart" entrypoint script that handles both web server startup and one-off commands.

# Exit immediately if a command exits with a non-zero status.
set -e

# The first argument ($1) is the command we want to run.
# Check if the command is 'gunicorn', which is our default command for the web server.
if [ "$1" = 'gunicorn' ]; then
    # --- WEB SERVER STARTUP LOGIC ---
    echo "Entrypoint: Detected Gunicorn command. Starting web server."
    
    # The "wait for db" logic belongs here, because only the web server
    # needs to wait for the database before starting.
    DB_HOST="db"
    DB_PORT="3306"
    echo "Waiting for database at ${DB_HOST}:${DB_PORT}..."
    while ! nc -z ${DB_HOST} ${DB_PORT}; do
      sleep 1 # wait for 1 second before trying again
    done
    echo "Database is up - starting application..."
    
    # 'exec' replaces the shell process with the gunicorn process.
    # This is important for correct signal handling (like Ctrl+C).
    exec "$@"

fi

# --- ONE-OFF COMMAND LOGIC ---
# If the first argument is anything else (e.g., 'python', 'sh', 'ls'),
# we assume it's a one-off command for development or CI.
# We skip the database check and just execute the command directly.
echo "Entrypoint: Running one-off command: $@"
exec "$@"