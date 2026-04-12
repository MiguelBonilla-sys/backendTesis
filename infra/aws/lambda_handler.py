"""
AWS Lambda entry point for BackendTesis FastAPI application.

Uses Mangum as the ASGI adapter to run FastAPI on AWS Lambda.
Deploy this file as the Lambda handler, or include it in the container image.

Handler reference: lambda_handler.handler
"""

from mangum import Mangum

from main import app

# lifespan="auto" lets Mangum fire the FastAPI startup/shutdown events
# on the first request of each cold start and on container shutdown.
handler = Mangum(app, lifespan="auto")
