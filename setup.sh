#!/bin/bash

# Define color codes
BLUE='\033[1;34m'
ORANGE='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to handle errors
handle_error() {
    echo -e "${RED}An error occurred. Cleaning up...${NC}"
    # Perform cleanup if needed
    exit 1
}

# Trap errors
trap 'handle_error' ERR

echo -e "${BLUE}Starting setup script...${NC}"

# Update the system
echo -e "${BLUE}Updating the system...${NC}"
sudo apt-get update -y && sudo apt-get upgrade -y

# Install necessary packages for Docker installation
echo -e "${BLUE}Installing necessary packages...${NC}"
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common

# Install Docker if it's not installed
if ! [ -x "$(command -v docker)" ]; then
    echo -e "${BLUE}Docker is not installed. Installing Docker...${NC}"
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    rm get-docker.sh
else
    echo -e "${BLUE}Docker is already installed.${NC}"
fi

# Add current user to the Docker group
echo -e "${BLUE}Adding current user to the Docker group...${NC}"
sudo usermod -aG docker $USER

# Create run.sh script to run the honeypot server
echo -e "${BLUE}Creating run.sh script...${NC}"
cat <<EOL > run.sh
#!/bin/bash
echo -e "${BLUE}Running the Docker container...${NC}"
docker run -d -p 80:80 -p 21:21 -p 22:22 -p 23:23 -p 25:25 -p 110:110 honeypot-server
if [ \$? -eq 0 ]; then
    echo -e "${BLUE}Honeypot server is running.${NC}"
else
    echo -e "${RED}There was an error starting the Docker container. Check the logs for more details.${NC}"
fi
EOL

# Make run.sh executable
chmod +x run.sh

# Build the Docker image
echo -e "${BLUE}Building the Docker image...${NC}"
docker build -t honeypot-server .

# Run the honeypot server
./run.sh

# Cleanup: Remove the setup.sh script
echo -e "${BLUE}Setup complete. Removing setup script...${NC}"
rm -- "$0"
