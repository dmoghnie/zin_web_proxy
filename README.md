# Zin Web Proxy

A full-featured web proxy similar to CroxyProxy that allows browsing websites through a proxy with support for images, CSS, JavaScript and other resources.

## Features

- **Complete Resource Proxying**: Handles HTML, CSS, JavaScript, images and all other web resources
- **URL Rewriting**: Automatically rewrites all URLs in HTML, CSS, and JavaScript to route through the proxy
- **Session Management**: Maintains cookies and session state for websites requiring login
- **JavaScript Support**: Advanced handling of dynamically loaded content via JavaScript
- **DOM Monitoring**: Uses MutationObserver to rewrite URLs added by JavaScript after page load
- **Browser History**: Tracks browsing history for easy navigation between sites
- **CORS Bypass**: Circumvents cross-origin restrictions
- **Private Browsing**: Create new sessions with isolated cookies

## Installation

1. Clone this repository:
```
git clone https://github.com/yourusername/zin-web-proxy.git
cd zin-web-proxy
```

2. Install dependencies:
```
npm install
```

3. Start the server:
```
npm start
```

The server will run on http://localhost:3000 by default.

## Development

To run the server with auto-reload during development:
```
npm run dev
```

## Usage

1. Open your browser and go to http://localhost:3000
2. Enter the URL of the website you want to access
3. Click "Browse" to access the website through the proxy
4. For a new session with fresh cookies, click "New Session"

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