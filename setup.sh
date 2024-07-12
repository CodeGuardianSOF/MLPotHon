#!/bin/bash

# Define color codes
BLUE='\033[1;34m'
ORANGE='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

LOGFILE="setup.log"
DOCKER_USER="$(whoami)"
DOCKER_COMPOSE_VERSION="1.29.2"

# Function to handle errors
handle_error() {
    echo -e "${RED}An error occurred. Cleaning up...${NC}"
    echo "Error details can be found in $LOGFILE"
    exit 1
}

# Trap errors
trap 'handle_error' ERR

# Redirect all output to log file
exec > >(tee -i $LOGFILE)
exec 2>&1

echo -e "${BLUE}Starting setup script...${NC}"

# Function to retry a command up to a specified number of times
retry() {
    local n=1
    local max=5
    local delay=5
    while true; do
        "$@" && break || {
            if [[ $n -lt $max ]]; then
                ((n++))
                echo -e "${ORANGE}Command failed. Attempt $n/$max in $delay seconds...${NC}"
                sleep $delay;
            else
                echo -e "${RED}The command has failed after $n attempts.${NC}"
                return 1
            fi
        }
    done
}

# Update the system
echo -e "${BLUE}Updating the system...${NC}"
retry sudo apt-get update -y
retry sudo apt-get upgrade -y

# Install necessary dependencies
echo -e "${BLUE}Installing dependencies...${NC}"
retry sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
echo -e "${BLUE}Adding Docker's official GPG key...${NC}"
retry curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Determine the distribution and codename
distro=$(lsb_release -is | tr '[:upper:]' '[:lower:]')
codename=$(lsb_release -cs)

# For Kali Linux, use Debian's codename "bullseye"
if [[ "$distro" == "kali" ]]; then
    codename="bullseye"
fi

# Remove any existing Docker list files
echo -e "${BLUE}Removing any existing Docker list files...${NC}"
sudo rm -f /etc/apt/sources.list.d/docker.list

# Set up the Docker repository
echo -e "${BLUE}Setting up the Docker repository for $distro $codename...${NC}"
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $codename stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update package database with Docker packages
echo -e "${BLUE}Updating package database...${NC}"
retry sudo apt-get update -y

# Install Docker
echo -e "${BLUE}Installing Docker...${NC}"
retry sudo apt-get install -y docker-ce docker-ce-cli containerd.io

# Verify Docker installation
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker installation failed. Check the log for details.${NC}"
    exit 1
fi

# Ensure Docker service is running
echo -e "${BLUE}Ensuring Docker service is running...${NC}"
sudo systemctl enable docker
sudo systemctl start docker
if ! sudo systemctl is-active --quiet docker; then
    echo -e "${RED}Docker service is not running. Please check the log for details.${NC}"
    exit 1
fi

# Install Docker Compose
echo -e "${BLUE}Installing Docker Compose...${NC}"
retry sudo curl -L "https://github.com/docker/compose/releases/download/$DOCKER_COMPOSE_VERSION/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
retry sudo chmod +x /usr/local/bin/docker-compose

# Verify Docker Compose installation
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Docker Compose installation failed. Check the log for details.${NC}"
    exit 1
fi

# Add current user to the Docker group
echo -e "${BLUE}Adding current user to the Docker group...${NC}"
sudo usermod -aG docker $DOCKER_USER

# Inform user to log out and back in
echo -e "${ORANGE}Please log out and log back in to apply Docker group changes, or run 'newgrp docker' to apply the changes immediately.${NC}"

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
if docker build -t honeypot-server .; then
    echo -e "${BLUE}Docker image built successfully.${NC}"
else
    echo -e "${RED}Docker image build failed. Check the log for details.${NC}"
    exit 1
fi

# Run the honeypot server
./run.sh

# Verify that the honeypot server is running
if docker ps -q -f name=honeypot-server | grep -q .; then
    echo -e "${BLUE}Honeypot server is running.${NC}"
else
    echo -e "${RED}Honeypot server failed to start. Check the log for details.${NC}"
    exit 1
fi

# Cleanup: Remove the setup script and log file
echo -e "${BLUE}Setup complete. Removing setup script and log file...${NC}"
rm -- "$0" $LOGFILE

echo -e "${BLUE}Setup script completed successfully.${NC}"
