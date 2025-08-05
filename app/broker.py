# app/broker.py (Final, Robust Version)
import dramatiq
from dramatiq.brokers.redis import RedisBroker
from redis import ConnectionPool

# --- THIS IS THE FIX ---
# 1. Create an explicit Redis Connection Pool.
#    This forces all connections to use the correct 'redis' hostname.
pool = ConnectionPool(host="redis", port=6379, db=0)

# 2. Pass the pre-configured pool to the broker.
#    This overrides any internal defaults that might be incorrectly pointing to 'localhost'.
redis_broker = RedisBroker(connection_pool=pool)
# --- END OF FIX ---

# Set the broker for any process that imports this file.
dramatiq.set_broker(redis_broker)