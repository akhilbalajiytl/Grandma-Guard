#!/bin/bash
# entrypoint.sh (Final, Robust Orchestrator)

set -e

# Default to "web" if no command is provided
COMMAND=${1:-web}

echo "Entrypoint received command: $COMMAND"

# Only run the database wait logic for services that need the database on startup.
if [[ "$COMMAND" == "web" || "$COMMAND" == "worker" || "$COMMAND" == "init_db" ]]; then
  
  # Extract DB connection details from DATABASE_URL
  DB_USER=$(echo $DATABASE_URL | awk -F':' '{print $2}' | awk -F'/' '{print $3}')
  DB_PASS=$(echo $DATABASE_URL | awk -F'@' '{print $1}' | awk -F':' '{print $3}')
  DB_HOST=$(echo $DATABASE_URL | awk -F'@' '{print $2}' | awk -F'/' '{print $1}' | awk -F':' '{print $1}')

  echo "Waiting for database at $DB_HOST..."

  # Use mysqladmin ping, the most reliable check. Waits up to 120 seconds.
  MAX_RETRIES=24
  i=0
  export MYSQL_PWD=$DB_PASS
  
  until mysqladmin ping -h "$DB_HOST" -u "$DB_USER" --silent; do
    i=$((i+1))
    if [ $i -ge $MAX_RETRIES ]; then
      echo "Database ($DB_HOST) did not become available in time."
      exit 1
    fi
    echo -n "."
    sleep 5
  done
  
  unset MYSQL_PWD
  echo "Database is up and responsive!"
fi

if [ "$COMMAND" = "web" ]; then
  echo "Starting Web application..."
  exec gunicorn -c gunicorn.conf.py asgi:app

elif [ "$COMMAND" = "init_db" ]; then
  echo "Running database initialization script..."
  exec python init_db.py

else
  # This is a generic "pass-through" for any other command.
  # It will execute the command we defined in docker-compose.yml,
  # like "python -m dramatiq app.dramatiq_setup -p 1 --queues gpu"
  echo "Executing custom command: $@"
  exec "$@"
fi