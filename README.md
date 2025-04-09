# Zin Web Proxy

A robust web proxy server for proxying HTTPS traffic.

## Features

- Full HTTP/HTTPS proxying support
- WebSocket support for real-time applications
- Advanced HTML rewriting to handle links, forms, and JavaScript redirects
- Cookie management across requests
- Support for ASPX applications
- HTTPS server capabilities
- Automatic Let's Encrypt certificate management

## Setup

### Quick Start

```bash
# Build the Docker image
docker build -t zin-web-proxy .

# Run with HTTP
docker run -d -p 82:3000 zin-web-proxy

# Or run with port mapping of your choice
docker run -d -p <host-port>:3000 zin-web-proxy
```

### Using HTTPS

#### Option 1: Self-signed certificates (for development)

Generate self-signed certificates:

```bash
mkdir -p ssl
openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes
```

Run with HTTPS enabled:
```bash
docker run -d -p 443:3000 \
  -v $(pwd)/ssl:/app/ssl \
  -e USE_HTTPS=true \
  zin-web-proxy
```

#### Option 2: Automatic Let's Encrypt certificates (recommended for production)

The proxy can automatically request and renew Let's Encrypt certificates:

```bash
# IMPORTANT: Port 80 MUST be mapped to port 80 for Let's Encrypt validation to work
docker run -d \
  -p 443:3000 \
  -p 80:80 \
  -e USE_HTTPS=true \
  -e USE_LETSENCRYPT=true \
  -e LETSENCRYPT_EMAIL=your-email@example.com \
  -e LETSENCRYPT_DOMAIN=your-domain.com \
  -e LETSENCRYPT_PRODUCTION=true \
  -v letsencrypt-certs:/app/ssl \
  zin-web-proxy
```

> **IMPORTANT:** For Let's Encrypt to work properly:
> 1. Your server MUST be publicly accessible on the internet
> 2. Port 80 MUST be mapped correctly and accessible from the internet (for ACME challenge)
> 3. The domain name (LETSENCRYPT_DOMAIN) must point to your server's public IP address
> 4. Do not use port mapping like 8080:80 - it must be 80:80 for Let's Encrypt validation

For debugging Let's Encrypt issues, visit:
```
http://your-domain.com/.well-known/acme-challenge-debug
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| PORT | Port to run the server on | 3000 |
| USE_HTTPS | Enable HTTPS for the proxy server | false |
| VERIFY_SSL | Verify SSL certificates of target sites | true |
| SSL_KEY_PATH | Path to SSL private key | /app/ssl/key.pem |
| SSL_CERT_PATH | Path to SSL certificate | /app/ssl/cert.pem |
| USE_LETSENCRYPT | Use Let's Encrypt for certificates | false |
| LETSENCRYPT_EMAIL | Email for Let's Encrypt registration | admin@example.com |
| LETSENCRYPT_DOMAIN | Domain name for the certificate | localhost |
| LETSENCRYPT_PRODUCTION | Use Let's Encrypt production (vs staging) | false |

## Usage

Access the proxy at:
- HTTP mode: `http://localhost:<port>/proxy?url=https://example.com`
- WebSocket support: `http://localhost:<port>/direct-proxy?url=https://example.com`

For HTTPS mode, replace http with https in the proxy URLs.

## Technical Details

This proxy handles several technical challenges:

1. **HTML Transformation**: Uses Cheerio to parse and modify HTML content, rewriting all URLs
2. **CSS Processing**: Rewrites `url()` references in CSS files and style tags
3. **JavaScript Interception**: Overrides `fetch` and `XMLHttpRequest` to route through the proxy
4. **DOM Mutation Monitoring**: Uses MutationObserver to catch dynamically added elements
5. **Cookie Management**: Maintains isolated cookie jars for different browsing sessions
6. **Content Type Detection**: Processes different content types appropriately (HTML, CSS, binary)

## Limitations

- Some websites with advanced anti-proxy measures may detect and block proxy usage
- Certain complex JavaScript applications may not function correctly
- WebSocket connections might not work properly in some cases
- Some websites with strict CORS policies may still block certain functionality

## License

MIT