# Use the official Python base image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Set the working directory
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Copy the rest of the application code
COPY . .

# Ensure the configuration directory exists
RUN mkdir -p cfg

# Expose the ports that the honeypot will listen on
EXPOSE 80 21 22 23 25 110

# Run the honeypot server
CMD ["python", "honeypot/honeypot.py"]
