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
    local error_message="$1"
    echo -e "${RED}${error_message}${NC}"
    echo -e "${RED}Cleaning up...${NC}"
    echo "Error details can be found in $LOGFILE"
    exit 1
}

# Trap errors
trap 'handle_error "An unexpected error occurred. Check the log for details."' ERR

# Redirect all output to log file
exec > >(tee -i $LOGFILE)
exec 2>&1

echo -e "${BLUE}Starting setup script...${NC}"

# Check if required commands are available
for cmd in curl gpg lsb_release dpkg sudo; do
    if ! command -v $cmd &> /dev/null; then
        handle_error "Required command $cmd is not available. Please install it and try again."
    fi
done

# Function to retry a command up to a specified number of times
retry() {
    local n=1
    local max=5
    local delay=5
    while true; do
        "$@" && break || {
            if [[ $n -lt $max ]]; then
                ((n++))
                echo -e "${ORANGE}Command failed: $*. Attempt $n/$max in $delay seconds...${NC}"
                sleep $delay
            else
                handle_error "The command '$*' has failed after $n attempts."
            fi
        }
    done
}

# Function to update the system
update_system() {
    echo -e "${BLUE}Updating the system...${NC}"
    retry sudo apt-get update -y
    retry sudo apt-get upgrade -y
}

# Function to install dependencies
install_dependencies() {
    echo -e "${BLUE}Installing dependencies...${NC}"
    retry sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
}

# Function to add Docker's GPG key
add_docker_gpg_key() {
    echo -e "${BLUE}Adding Docker's official GPG key...${NC}"
    retry curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
}

# Function to setup Docker repository
setup_docker_repo() {
    echo -e "${BLUE}Setting up the Docker repository...${NC}"
    local distro=$(lsb_release -is | tr '[:upper:]' '[:lower:]')
    local codename=$(lsb_release -cs)

    # For Kali Linux, use Debian's codename "bullseye"
    if [[ "$distro" == "kali" ]]; then
        codename="bullseye"
    fi

    echo -e "${BLUE}Removing any existing Docker list files...${NC}"
    sudo rm -f /etc/apt/sources.list.d/docker.list

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $codename stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    echo -e "${BLUE}Updating package database...${NC}"
    retry sudo apt-get update -y
}

# Function to install Docker
install_docker() {
    echo -e "${BLUE}Installing Docker...${NC}"
    retry sudo apt-get install -y docker-ce docker-ce-cli containerd.io
}

# Function to verify Docker installation
verify_docker_installation() {
    if ! command -v docker &> /dev/null; then
        handle_error "Docker installation failed. Check the log for details."
    fi

    echo -e "${BLUE}Ensuring Docker service is running...${NC}"
    sudo systemctl enable docker
    sudo systemctl start docker
    if ! sudo systemctl is-active --quiet docker; then
        handle_error "Docker service is not running. Please check the log for details."
    fi
}

# Function to install Docker Compose
install_docker_compose() {
    echo -e "${BLUE}Installing Docker Compose...${NC}"
    retry sudo curl -L "https://github.com/docker/compose/releases/download/$DOCKER_COMPOSE_VERSION/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    retry sudo chmod +x /usr/local/bin/docker-compose

    if ! command -v docker-compose &> /dev/null; then
        handle_error "Docker Compose installation failed. Check the log for details."
    fi
}

# Function to add user to Docker group
add_user_to_docker_group() {
    echo -e "${BLUE}Adding current user to the Docker group...${NC}"
    sudo usermod -aG docker $DOCKER_USER
    echo -e "${ORANGE}Please log out and log back in to apply Docker group changes, or run 'newgrp docker' to apply the changes immediately.${NC}"
}

# Function to create run.sh script
create_run_script() {
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

    chmod +x run.sh
}

# Function to build the Docker image
build_docker_image() {
    echo -e "${BLUE}Building the Docker image...${NC}"
    if docker build -t honeypot-server .; then
        echo -e "${BLUE}Docker image built successfully.${NC}"
    else
        handle_error "Docker image build failed. Check the log for details."
    fi
}

run_honeypot_server() {
    echo -e "${BLUE}Running the Docker container...${NC}"
    if docker ps -q -f name=honeypot-server | grep -q .; then
        echo -e "${ORANGE}Honeypot server container is already running.${NC}"
    else
        docker run -d --name honeypot-server -p 80:80 -p 21:21 -p 22:22 -p 23:23 -p 25:25 -p 110:110 honeypot-server
        if [ $? -eq 0 ]; then
            echo -e "${BLUE}Honeypot server is running.${NC}"
        else
            handle_error "There was an error starting the Docker container. Check the logs for more details."
        fi
    fi
}

# Function to verify that the honeypot server is running
verify_honeypot_server() {
    if docker ps -q -f name=honeypot-server | grep -q .; then
        echo -e "${BLUE}Honeypot server is running.${NC}"
    else
        handle_error "Honeypot server failed to start. Check the log for details."
    fi
}

# Function to cleanup
cleanup() {
    echo -e "${BLUE}Setup complete. Removing setup script and log file...${NC}"
    rm -- "$0" $LOGFILE
}

# Main script execution
main() {
    update_system
    install_dependencies
    add_docker_gpg_key
    setup_docker_repo
    install_docker
    verify_docker_installation
    install_docker_compose
    add_user_to_docker_group
    create_run_script
    build_docker_image
    run_honeypot_server
    cleanup
    echo -e "${BLUE}Setup script completed successfully.${NC}"
}

main "$@"
