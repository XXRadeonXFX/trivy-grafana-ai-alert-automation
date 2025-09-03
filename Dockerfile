# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN pip install --no-cache-dir --upgrade pip

# Install requirements
RUN pip install --no-cache-dir -r requirements.txt

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Define environment variable
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Create a script to run tests or the application
RUN mkdir -p test-reports

RUN echo '#!/bin/bash\n\
if [ "$RUN_TESTS" = "true" ]; then\n\
    pytest test_app.py --maxfail=1 --disable-warnings --junitxml=test-reports/test-results.xml\n\
else\n\
    flask run --host=0.0.0.0 --port=8000\n\
fi' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Run the entrypoint script
CMD ["/app/entrypoint.sh"]

