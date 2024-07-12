# Use Python 3.12 slim variant as the base image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Set the working directory
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt ./
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir --upgrade -r requirements.txt

# Copy the configuration directory and the rest of the application code to /app
COPY cfg/ /app/cfg/
COPY . /app

# Ensure the logs and malware directories exist
RUN mkdir -p /app/logs /app/malware

# Expose the ports that the honeypot will listen on
EXPOSE 80 21 22 23 25 110

# Run the honeypot server
CMD ["python", "honeypot/honeypot.py"]
