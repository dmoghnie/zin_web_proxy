#!/bin/bash
# Script to help set up and run the Zin Web Proxy with proper SSL certificate handling

# Default values
PORT=3000
USE_HTTPS=false
SSL_SOURCE="self-signed"  # Options: self-signed, external, letsencrypt
DOMAIN="localhost"
EMAIL="admin@example.com"
PRODUCTION=false
EXTERNAL_CERT_PATH=""
EXTERNAL_KEY_PATH=""

# Show help
show_help() {
  echo "Zin Web Proxy - SSL Setup Helper"
  echo ""
  echo "Usage: ./start.sh [options]"
  echo ""
  echo "Options:"
  echo "  -p, --port PORT              Port to run on (default: 3000)"
  echo "  -s, --ssl SOURCE             SSL source: self-signed, external, letsencrypt (default: self-signed)"
  echo "  -d, --domain DOMAIN          Domain name for HTTPS (default: localhost)"
  echo "  -e, --email EMAIL            Email for Let's Encrypt registration"
  echo "  --production                 Use Let's Encrypt production (not staging)"
  echo "  -c, --cert PATH              Path to external SSL certificate"
  echo "  -k, --key PATH               Path to external SSL key"
  echo "  -h, --help                   Show this help"
  echo ""
  echo "Examples:"
  echo "  ./start.sh --ssl self-signed                 # Generate and use self-signed certificates"
  echo "  ./start.sh --ssl letsencrypt --domain example.com --email admin@example.com"
  echo "  ./start.sh --ssl external --cert /path/to/cert.pem --key /path/to/key.pem"
  echo ""
}

# Parse arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -p|--port)
      PORT="$2"
      shift 2
      ;;
    -s|--ssl)
      SSL_SOURCE="$2"
      USE_HTTPS=true
      shift 2
      ;;
    -d|--domain)
      DOMAIN="$2"
      shift 2
      ;;
    -e|--email)
      EMAIL="$2"
      shift 2
      ;;
    --production)
      PRODUCTION=true
      shift
      ;;
    -c|--cert)
      EXTERNAL_CERT_PATH="$2"
      shift 2
      ;;
    -k|--key)
      EXTERNAL_KEY_PATH="$2"
      shift 2
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      show_help
      exit 1
      ;;
  esac
done

# Create ssl directory if it doesn't exist
mkdir -p ssl

# Handle SSL setup based on source
if [ "$USE_HTTPS" = true ]; then
  case $SSL_SOURCE in
    "self-signed")
      echo "Generating self-signed certificates..."
      if [ ! -f ssl/key.pem ] || [ ! -f ssl/cert.pem ]; then
        openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes -subj "/CN=${DOMAIN}"
        echo "Self-signed certificates generated successfully."
      else
        echo "Using existing certificates in ssl/ directory."
      fi
      
      DOCKER_CMD="docker run -d \
        -p ${PORT}:3000 \
        -v $(pwd)/ssl:/app/ssl \
        -e USE_HTTPS=true \
        -e USE_LETSENCRYPT=false \
        zin-web-proxy"
      ;;
      
    "letsencrypt")
      echo "Setting up with Let's Encrypt for domain ${DOMAIN}..."
      
      DOCKER_CMD="docker run -d \
        -p ${PORT}:3000 \
        -p 80:80 \
        -v $(pwd)/ssl:/app/ssl \
        -e USE_HTTPS=true \
        -e USE_LETSENCRYPT=true \
        -e LETSENCRYPT_EMAIL=${EMAIL} \
        -e LETSENCRYPT_DOMAIN=${DOMAIN} \
        -e LETSENCRYPT_PRODUCTION=${PRODUCTION} \
        zin-web-proxy"
      ;;
      
    "external")
      if [ -z "$EXTERNAL_CERT_PATH" ] || [ -z "$EXTERNAL_KEY_PATH" ]; then
        echo "Error: External certificate and key paths must be provided."
        exit 1
      fi
      
      echo "Using external certificates..."
      
      # Copy certificates to local ssl directory
      cp "$EXTERNAL_CERT_PATH" ssl/cert.pem
      cp "$EXTERNAL_KEY_PATH" ssl/key.pem
      
      DOCKER_CMD="docker run -d \
        -p ${PORT}:3000 \
        -v $(pwd)/ssl:/app/ssl \
        -e USE_HTTPS=true \
        -e USE_LETSENCRYPT=false \
        zin-web-proxy"
      ;;
      
    *)
      echo "Unknown SSL source: $SSL_SOURCE"
      exit 1
      ;;
  esac
else
  # HTTP mode
  DOCKER_CMD="docker run -d -p ${PORT}:3000 zin-web-proxy"
fi

# Build Docker image if it doesn't exist
if [[ "$(docker images -q zin-web-proxy 2> /dev/null)" == "" ]]; then
  echo "Building Docker image..."
  docker build -t zin-web-proxy .
fi

# Run the Docker container
echo "Starting Zin Web Proxy..."
echo $DOCKER_CMD
eval $DOCKER_CMD

echo "Zin Web Proxy is now running!"
if [ "$USE_HTTPS" = true ]; then
  echo "Access at: https://localhost:${PORT} (or https://${DOMAIN}:${PORT})"
else
  echo "Access at: http://localhost:${PORT}"
fi 