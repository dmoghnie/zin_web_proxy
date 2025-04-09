FROM node:18-alpine

# Install curl for ACME challenge testing
RUN apk add --no-cache curl

# Create app directory
WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p public
RUN mkdir -p ssl
RUN mkdir -p ssl/acme-challenge
RUN chmod -R 755 ssl

# Default environment variables
ENV PORT=3000
ENV USE_HTTPS=false
ENV VERIFY_SSL=true
ENV SSL_KEY_PATH=/app/ssl/key.pem
ENV SSL_CERT_PATH=/app/ssl/cert.pem
ENV USE_LETSENCRYPT=false
ENV LETSENCRYPT_EMAIL=admin@example.com
ENV LETSENCRYPT_DOMAIN=localhost
ENV LETSENCRYPT_PRODUCTION=false

# Expose the port the app runs on
EXPOSE 3000
# Also expose port 80 for Let's Encrypt HTTP challenge - MUST be exposed
EXPOSE 80

# Command to run the application
CMD ["node", "src/index.js"] 