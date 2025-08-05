"""
GrandmaGuard Dramatiq Worker Configuration Module

This module provides the isolated configuration and initialization for
Dramatiq background task workers in the GrandmaGuard security assessment
platform. It serves as the dedicated entry point for worker processes,
ensuring clean separation from the main Flask application to prevent
initialization conflicts and dependency issues.

Core Purpose:
- Isolated Dramatiq worker configuration without Flask app dependencies
- Redis broker setup for reliable task queue management
- Task discovery and registration for backNregressionground processing
- Prevention of database initialization race conditions

Architectural Design:
This module is specifically designed to avoid importing the main Flask
application during worker initialization, preventing circular dependencies
and database connection conflicts that can occur when both web and worker
processes attempt to initialize the same resources simultaneously.

Worker Process Architecture:
- Dedicated worker processes separate from web application
- Redis-based message broker for reliable task delivery
- Automatic task discovery and actor registration
- Clean separation of concerns between web and background processing

Key Benefits:
- Prevents Flask app initialization in worker processes
- Eliminates database connection race conditions
- Enables independent scaling of worker processes
- Provides fault isolation between web and background operations
- Supports horizontal scaling of analysis capabilities

Task Queue Configuration:
- Redis broker for high-performance message queuing
- Reliable task delivery with automatic retry mechanisms
- Dead letter queues for failed task analysis
- Worker process isolation and resource management

Usage:
This module should be used as the entry point for Dramatiq worker processes:

    # Start Dramatiq worker process
    dramatiq app.dramatiq_setup

The worker process will:
1. Initialize Redis broker connection
2. Discover and register background tasks
3. Begin processing queued security analysis tasks
4. Operate independently from the web application

Dependencies:
- Dramatiq: Distributed task processing framework
- Redis: Message broker and task queue backend
- Background tasks module: Contains actual task implementations

Production Deployment:
- Run worker processes separately from web application
- Scale worker instances based on analysis workload
- Monitor worker health and task queue performance
- Configure Redis for high availability and persistence

Author: GrandmaGuard Security Team
License: MIT
"""

# app/dramatiq_setup.py
# Import the broker file. This executes the code inside it,
# creating and setting the global broker instance.
from . import broker

# Now, import the tasks. Dramatiq will automatically discover them
# and attach them to the broker that was just set.
from . import tasks