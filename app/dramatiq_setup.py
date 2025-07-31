# app/dramatiq_setup.py
import dramatiq
from dramatiq.brokers.redis import RedisBroker

# This file is the SOLE entrypoint for the Dramatiq worker.
# It does NOT import the main Flask app, thus avoiding the database
# initialization race condition.

# 1. Configure the Broker
redis_broker = RedisBroker(host="redis")
dramatiq.set_broker(redis_broker)

# 2. Import the tasks file so Dramatiq discovers the actors.
#    The tasks.py file itself should have no top-level app imports.
from . import tasks