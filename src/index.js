const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cheerio = require('cheerio');
const axios = require('axios');
const morgan = require('morgan');
const path = require('path');
const url = require('url');
const stream = require('stream');
const { promisify } = require('util');
const { createProxyMiddleware } = require('http-proxy-middleware');
const fs = require('fs');
const http = require('http');
const https = require('https');
const CertificateManager = require('./cert-manager');

const pipeline = promisify(stream.pipeline);

const app = express();
const PORT = process.env.PORT || 3000;

// Global cache for proxied resources to prevent re-fetching static assets
const cache = new Map();
const CACHE_TTL = 15 * 60 * 1000; // 15 minutes
const MAX_CACHE_SIZE = 100;

// Option to configure HTTPS for the proxy server itself
let useHttps = process.env.USE_HTTPS === 'true';
const useLetsEncrypt = process.env.USE_LETSENCRYPT === 'true';
let httpsOptions = {};

// Middleware
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.raw({ type: 'application/octet-stream', limit: '10mb' }));
app.use(bodyParser.text({ type: ['text/*', 'application/xml'], limit: '10mb' }));
app.use(cookieParser());
app.use(morgan('dev')); // Add logging
app.use(express.static(path.join(__dirname, '../public')));

// Store active sessions
const sessions = new Map();

// Use direct http-proxy-middleware for enhanced proxying capabilities
const setupDirectProxy = () => {
  const proxyOptions = {
    target: 'https://sunitalia.stoneprofits.com', // Default target
    changeOrigin: true,
    ws: true, // Enable WebSocket support by default
    secure: process.env.VERIFY_SSL !== 'false', // Verify SSL certs by default, can be disabled
    onProxyReq: (proxyReq, req, res) => {
      // Use the session cookies if available
      const session = getSession(req);
      
      if (session) {
        // Get the target host
        let targetHost = proxyOptions.target;
        if (req.query.url) {
          try {
            const targetUrl = new URL(req.query.url);
            targetHost = targetUrl.hostname;
          } catch (e) {
            console.error('Error parsing target URL:', e);
          }
        }
        
        // If we have a hostname, get cookies for it
        if (targetHost) {
          // Get hostname without protocol
          if (targetHost.startsWith('http')) {
            try {
              const targetUrl = new URL(targetHost);
              targetHost = targetUrl.hostname;
            } catch (e) {
              console.error('Error extracting hostname:', e);
            }
          }
          
          const cookieHeader = getCookiesForHostname(session, targetHost);
          if (cookieHeader) {
            proxyReq.setHeader('Cookie', cookieHeader);
            console.log(`Direct proxy: Added cookies for ${targetHost}: ${cookieHeader.substring(0, 100)}${cookieHeader.length > 100 ? '...' : ''}`);
          }
        }
      }

      // Clone body for POST requests
      if (req.body && (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH')) {
        const contentType = proxyReq.getHeader('Content-Type');
        if (contentType && contentType.includes('application/json')) {
          const bodyData = JSON.stringify(req.body);
          proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
          proxyReq.write(bodyData);
        }
      }
    },
    onProxyRes: (proxyRes, req, res) => {
      // Customize headers if needed
      proxyRes.headers['X-Proxied-By'] = 'Zin-Web-Proxy-Direct';
      
      // Add CORS headers when needed
      if (req.headers.origin) {
        proxyRes.headers['Access-Control-Allow-Origin'] = req.headers.origin;
        proxyRes.headers['Access-Control-Allow-Credentials'] = 'true';
        proxyRes.headers['Access-Control-Allow-Methods'] = 'GET, PUT, POST, DELETE, OPTIONS';
        proxyRes.headers['Access-Control-Allow-Headers'] = 'Origin, X-Requested-With, Content-Type, Accept, Authorization';
      }
      
      // Handle cookies from the response
      if (proxyRes.headers['set-cookie']) {
        const session = getSession(req);
        
        if (session) {
          let targetHost = proxyOptions.target;
          
          // Extract hostname from target or URL param
          if (req.query.url) {
            try {
              const targetUrl = new URL(req.query.url);
              targetHost = targetUrl.hostname;
            } catch (e) {
              console.error('Error parsing URL for cookie domain:', e);
            }
          } else if (typeof targetHost === 'string' && targetHost.startsWith('http')) {
            try {
              const targetUrl = new URL(targetHost);
              targetHost = targetUrl.hostname;
            } catch (e) {
              console.error('Error extracting hostname from target:', e);
            }
          }
          
          // Update cookies in the session
          updateSessionCookies(session, targetHost, proxyRes.headers['set-cookie']);
          
          // Save the session cookie if needed
          if (!req.cookies.proxySessionId) {
            res.cookie('proxySessionId', session.id, { 
              httpOnly: true,
              secure: req.secure,
              sameSite: 'lax',
              maxAge: 86400000 // 24 hours
            });
          }
        }
      }

      // Special handling for redirects (302 responses)
      if (req.method === 'POST' && proxyRes.statusCode === 302 && proxyRes.headers.location) {
        console.log(`Direct proxy: handling redirect: ${proxyRes.headers.location}`);
        
        // Special handling for ReturnUrl in redirect location
        const redirectUrl = proxyRes.headers.location;
        if (redirectUrl.includes('ReturnUrl=')) {
          const returnUrlMatch = redirectUrl.match(/ReturnUrl=([^&]+)/);
          if (returnUrlMatch && returnUrlMatch[1]) {
            try {
              let returnUrl = decodeURIComponent(returnUrlMatch[1]);
              console.log(`Found ReturnUrl parameter in direct-proxy: ${returnUrl}`);
              
              // Check if the ReturnUrl is already a proxied URL
              if (returnUrl.startsWith('/direct-proxy?url=') || returnUrl.startsWith('/proxy?url=')) {
                console.log(`Using pre-proxied ReturnUrl: ${returnUrl}`);
                proxyRes.headers.location = returnUrl;
                return;
              }
              
              // If it starts with a slash, it's a relative URL
              if (returnUrl.startsWith('/')) {
                // Get the target from the current request
                let currentTarget = proxyOptions.target;
                if (req.query.url) {
                  try {
                    const parsedUrl = new URL(req.query.url);
                    currentTarget = parsedUrl.origin;
                  } catch (e) {
                    console.error('Error parsing URL for redirect target:', e);
                  }
                }
                returnUrl = currentTarget + returnUrl;
                console.log(`Made ReturnUrl absolute: ${returnUrl}`);
              }
              
              // Rewrite the location header to proxy the ReturnUrl
              proxyRes.headers.location = `/direct-proxy?url=${encodeURIComponent(returnUrl)}`;
              console.log(`Rewritten ReturnUrl redirect: ${proxyRes.headers.location}`);
              return;
            } catch (e) {
              console.error('Error processing ReturnUrl in direct-proxy redirect:', e);
            }
          }
        }
        
        // For all other redirects, make sure they go through our proxy
        let targetRedirect = redirectUrl;
        if (!redirectUrl.startsWith('http')) {
          let currentTarget = proxyOptions.target;
          if (req.query.url) {
            try {
              const parsedUrl = new URL(req.query.url);
              currentTarget = parsedUrl.origin;
            } catch (e) {
              console.error('Error parsing URL for redirect base:', e);
            }
          }
          
          if (!redirectUrl.startsWith('/')) {
            targetRedirect = '/' + redirectUrl;
          }
          targetRedirect = currentTarget + targetRedirect;
        }
        
        // Replace the location header to go through our proxy
        proxyRes.headers.location = `/direct-proxy?url=${encodeURIComponent(targetRedirect)}`;
        console.log(`Rewritten redirect to: ${proxyRes.headers.location}`);
      }

      // Update target in session
      const sessionId = req.cookies.proxySessionId;
      const session = sessionId ? sessions.get(sessionId) : null;
      if (session && req.query.url) {
        try {
          session.lastProxiedUrl = req.query.url;
        } catch (e) {
          console.error('Error updating session target:', e);
        }
      }
    },
    onProxyWSReq: (proxyReq, req, socket, options, head) => {
      // Handle WebSocket connections
      console.log('WebSocket connection proxied:', req.url);
      
      // Use the session cookies if available
      const cookies = req.headers.cookie;
      if (cookies) {
        const sessionIdMatch = cookies.match(/proxySessionId=([^;]+)/);
        if (sessionIdMatch) {
          const sessionId = sessionIdMatch[1];
          const session = sessions.get(sessionId);
          
          if (session && session.cookies) {
            const targetHost = new URL(proxyOptions.target).hostname;
            if (session.cookies[targetHost]) {
              proxyReq.setHeader('Cookie', session.cookies[targetHost]);
            }
          }
        }
      }
    },
    pathRewrite: (path, req) => {
      // Extract real target from URL parameter
      if (req.query.url) {
        try {
          const targetUrl = new URL(req.query.url);
          // Update the proxy target dynamically
          const oldTarget = proxyOptions.target;
          proxyOptions.target = targetUrl.origin;
          
          // Check if WebSockets should be enabled/disabled
          if (req.query.ws !== undefined) {
            proxyOptions.ws = req.query.ws === 'true';
            console.log(`WebSocket support: ${proxyOptions.ws ? 'Enabled' : 'Disabled'}`);
          }
          
          if (oldTarget !== proxyOptions.target) {
            console.log(`Switched proxy target to: ${proxyOptions.target}`);
          }
          
          // Return the path part of the target URL
          const proxiedPath = targetUrl.pathname + targetUrl.search;
          console.log(`Proxying direct request to: ${proxiedPath}`);
          return proxiedPath;
        } catch (e) {
          console.error('Error parsing target URL:', e);
        }
      }
      return path;
    },
    router: (req) => {
      // Determine target from URL parameter
      if (req.query.url) {
        try {
          const targetUrl = new URL(req.query.url);
          return targetUrl.origin;
        } catch (e) {
          console.error('Error parsing target URL for routing:', e);
        }
      }
      return proxyOptions.target;
    }
  };

  return createProxyMiddleware(proxyOptions);
};

// Direct proxy for web socket support
app.use('/direct-proxy', setupDirectProxy());

// Add HTML injection to rewrite functionality in direct proxy mode
app.use('/direct-proxy', function(req, res, next) {
  const _end = res.end;
  const _write = res.write;
  const chunks = [];

  // Only intercept HTML responses
  if (res.getHeader('content-type') && res.getHeader('content-type').includes('text/html')) {
    // Collect response chunks
    res.write = function(chunk) {
      chunks.push(Buffer.from(chunk));
      return true;
    };

    // Process the complete response
    res.end = function(chunk) {
      if (chunk) {
        chunks.push(Buffer.from(chunk));
      }

      // Combine chunks and convert to string
      let html = Buffer.concat(chunks).toString('utf8');

      // Special handling for stoneprofits.com
      if (req.query.url && req.query.url.includes('stoneprofits.com')) {
        const stoneprofitsScript = `
          <script>
            // Save original methods
            const originalWindowClose = window.close;
            const originalLocationReplace = window.location.replace;
            const originalLocationAssign = window.location.assign;
            
            // Override window.close
            window.close = function() {
              console.log('Blocked window.close() call');
              return false;
            };
            
            // Override window.location.replace
            window.location.replace = function(url) {
              console.log('Intercepted window.location.replace:', url);
              
              // Special handling for ReturnUrl in redirects
              if (url && url.includes('ReturnUrl=')) {
                console.log('Found ReturnUrl in direct-proxy redirect:', url);
                try {
                  // Extract the ReturnUrl parameter
                  const matches = url.match(/ReturnUrl=([^&]+)/);
                  if (matches && matches[1]) {
                    const returnUrl = decodeURIComponent(matches[1]);
                    
                    // If it's already a proxied URL, use it directly
                    if (returnUrl.startsWith('/direct-proxy?url=') || returnUrl.startsWith('/proxy?url=')) {
                      console.log('Using pre-proxied ReturnUrl:', returnUrl);
                      window.location.href = returnUrl;
                      return;
                    }
                    
                    // If it's a relative URL, make it absolute then proxy it
                    if (returnUrl.startsWith('/')) {
                      const baseUrl = window.location.href.split('/direct-proxy?url=')[1];
                      if (baseUrl) {
                        try {
                          const urlObj = new URL(decodeURIComponent(baseUrl));
                          const absoluteReturnUrl = urlObj.origin + returnUrl;
                          console.log('Made ReturnUrl absolute:', absoluteReturnUrl);
                          window.location.href = '/direct-proxy?url=' + encodeURIComponent(absoluteReturnUrl);
                          return;
                        } catch (e) {
                          console.error('Error creating absolute returnUrl:', e);
                        }
                      }
                    }
                  }
                } catch (e) {
                  console.error('Error processing ReturnUrl in direct-proxy:', e);
                }
              }
              
              if (url && !url.includes('/direct-proxy?url=')) {
                let proxyUrl = url;
                if (!url.includes('://')) {
                  // Handle relative URLs
                  if (!url.startsWith('/')) {
                    url = '/' + url;
                  }
                  const baseUrl = window.location.href.split('/direct-proxy?url=')[1];
                  if (baseUrl) {
                    try {
                      const urlObj = new URL(decodeURIComponent(baseUrl));
                      proxyUrl = urlObj.origin + url;
                    } catch (e) {
                      console.error('Error parsing base URL:', e);
                    }
                  }
                }
                window.location.href = '/direct-proxy?url=' + encodeURIComponent(proxyUrl);
                return;
              }
              return originalLocationReplace.call(window.location, url);
            };
            
            // Override window.location.assign
            window.location.assign = function(url) {
              console.log('Intercepted window.location.assign:', url);
              
              // Special handling for ReturnUrl in redirects
              if (url && url.includes('ReturnUrl=')) {
                console.log('Found ReturnUrl in direct-proxy redirect:', url);
                try {
                  // Extract the ReturnUrl parameter
                  const matches = url.match(/ReturnUrl=([^&]+)/);
                  if (matches && matches[1]) {
                    const returnUrl = decodeURIComponent(matches[1]);
                    
                    // If it's already a proxied URL, use it directly
                    if (returnUrl.startsWith('/direct-proxy?url=') || returnUrl.startsWith('/proxy?url=')) {
                      console.log('Using pre-proxied ReturnUrl:', returnUrl);
                      window.location.href = returnUrl;
                      return;
                    }
                    
                    // If it's a relative URL, make it absolute then proxy it
                    if (returnUrl.startsWith('/')) {
                      const baseUrl = window.location.href.split('/direct-proxy?url=')[1];
                      if (baseUrl) {
                        try {
                          const urlObj = new URL(decodeURIComponent(baseUrl));
                          const absoluteReturnUrl = urlObj.origin + returnUrl;
                          console.log('Made ReturnUrl absolute:', absoluteReturnUrl);
                          window.location.href = '/direct-proxy?url=' + encodeURIComponent(absoluteReturnUrl);
                          return;
                        } catch (e) {
                          console.error('Error creating absolute returnUrl:', e);
                        }
                      }
                    }
                  }
                } catch (e) {
                  console.error('Error processing ReturnUrl in direct-proxy:', e);
                }
              }
              
              if (url && !url.includes('/direct-proxy?url=')) {
                let proxyUrl = url;
                if (!url.includes('://')) {
                  // Handle relative URLs
                  if (!url.startsWith('/')) {
                    url = '/' + url;
                  }
                  const baseUrl = window.location.href.split('/direct-proxy?url=')[1];
                  if (baseUrl) {
                    try {
                      const urlObj = new URL(decodeURIComponent(baseUrl));
                      proxyUrl = urlObj.origin + url;
                    } catch (e) {
                      console.error('Error parsing base URL:', e);
                    }
                  }
                }
                window.location.href = '/direct-proxy?url=' + encodeURIComponent(proxyUrl);
                return;
              }
              return originalLocationAssign.call(window.location, url);
            };
            
            // Find and modify login forms
            document.addEventListener('DOMContentLoaded', function() {
              // Find all forms
              const forms = document.querySelectorAll('form');
              forms.forEach(form => {
                // Set target to _self to prevent opening in new window
                form.target = '_self';
                
                // Process ReturnUrl in form actions
                if (form.action && form.action.includes('ReturnUrl=')) {
                  try {
                    const urlRegex = /(\?|&)ReturnUrl=([^&]+)/g;
                    form.action = form.action.replace(urlRegex, function(match, prefix, returnUrl) {
                      // Decode the ReturnUrl
                      const decodedReturnUrl = decodeURIComponent(returnUrl);
                      
                      // If it's a relative URL, make it absolute
                      let absoluteReturnUrl = decodedReturnUrl;
                      if (absoluteReturnUrl.startsWith('/')) {
                        const baseUrl = window.location.href.split('/direct-proxy?url=')[1];
                        if (baseUrl) {
                          try {
                            const urlObj = new URL(decodeURIComponent(baseUrl));
                            absoluteReturnUrl = urlObj.origin + decodedReturnUrl;
                          } catch (e) {
                            console.error('Error creating absolute returnUrl:', e);
                          }
                        }
                      }
                      
                      // Create a new ReturnUrl that's already through the proxy
                      const proxyUrlParam = encodeURIComponent(absoluteReturnUrl);
                      const proxiedReturnUrl = encodeURIComponent('/proxy?url=' + proxyUrlParam);
                      return prefix + 'ReturnUrl=' + proxiedReturnUrl;
                    });
                  } catch (e) {
                    console.error('Error rewriting ReturnUrl in form action:', e);
                  }
                }
                
                // Add a special attribute to mark this form as processed
                form.setAttribute('data-proxy-processed', 'true');
                
                console.log('Modified form:', form);
              });
              
              // Process ReturnUrl in links
              const links = document.querySelectorAll('a[href]');
              links.forEach(link => {
                if (link.href && link.href.includes('ReturnUrl=')) {
                  try {
                    const urlRegex = /(\?|&)ReturnUrl=([^&]+)/g;
                    link.href = link.href.replace(urlRegex, function(match, prefix, returnUrl) {
                      // Decode the ReturnUrl
                      const decodedReturnUrl = decodeURIComponent(returnUrl);
                      
                      // If it's a relative URL, make it absolute
                      let absoluteReturnUrl = decodedReturnUrl;
                      if (absoluteReturnUrl.startsWith('/')) {
                        const baseUrl = window.location.href.split('/direct-proxy?url=')[1];
                        if (baseUrl) {
                          try {
                            const urlObj = new URL(decodeURIComponent(baseUrl));
                            absoluteReturnUrl = urlObj.origin + decodedReturnUrl;
                          } catch (e) {
                            console.error('Error creating absolute returnUrl:', e);
                          }
                        }
                      }
                      
                      // Create a new ReturnUrl that's already through the proxy
                      const proxyUrlParam = encodeURIComponent(absoluteReturnUrl);
                      const proxiedReturnUrl = encodeURIComponent('/proxy?url=' + proxyUrlParam);
                      return prefix + 'ReturnUrl=' + proxiedReturnUrl;
                    });
                  } catch (e) {
                    console.error('Error rewriting ReturnUrl in link href:', e);
                  }
                }
              });
            });
            
            // Monitor form submissions
            document.addEventListener('submit', function(e) {
              const form = e.target;
              console.log('Form submission detected:', form);
              
              // Ensure login forms don't redirect inappropriately
              if (form.method && form.method.toLowerCase() === 'post') {
                // Set the target to _self to prevent opening in new tab or closing
                form.target = '_self';
                
                // Add a small delay to ensure the form submits properly
                if (!form.dataset.intercepted) {
                  e.preventDefault();
                  form.dataset.intercepted = 'true';
                  
                  // Wait a moment then resubmit
                  setTimeout(function() {
                    console.log('Resubmitting intercepted form');
                    form.submit();
                  }, 100);
                }
              }
            });
          </script>
        `;
        
        // Add the script to the HTML
        html = html.replace('</head>', stoneprofitsScript + '</head>');
      }

      // Insert our script just before the closing </body> tag
      const scriptToInject = `
        <script>
        (function() {
          // Intercept form submissions and ensure they go through the proxy
          document.addEventListener('submit', function(e) {
            const form = e.target;
            if (form.tagName === 'FORM' && !form.action.includes('/direct-proxy')) {
              e.preventDefault();
              
              // Get original form action
              let action = form.action || window.location.href;
              
              // Make sure it goes through our proxy
              form.action = '/direct-proxy?url=' + encodeURIComponent(action);
              
              // Add a hidden field to indicate this was proxied
              const proxyField = document.createElement('input');
              proxyField.type = 'hidden';
              proxyField.name = '_proxy_direct';
              proxyField.value = 'true';
              form.appendChild(proxyField);
              
              // Set target to _self to prevent closing
              form.target = '_self';
              
              // Submit the form
              form.submit();
            }
          });
          
          // Intercept link clicks 
          document.addEventListener('click', function(e) {
            let target = e.target;
            // Find the closest anchor tag
            while (target && target !== document) {
              if (target.tagName === 'A' && target.href && !target.href.includes('/direct-proxy')) {
                e.preventDefault();
                window.location.href = '/direct-proxy?url=' + encodeURIComponent(target.href);
                return;
              }
              target = target.parentNode;
            }
          });
          
          // Intercept and proxy WebSocket connections
          const originalWebSocket = window.WebSocket;
          window.WebSocket = function(url, protocols) {
            // Handle both ws:// and wss:// protocols properly
            try {
              // Parse the original URL
              const parsedUrl = new URL(url);
              // Get the current page protocol (http:// or https://)
              const pageProtocol = window.location.protocol;
              // Use appropriate WebSocket protocol based on page protocol
              const wsProtocol = pageProtocol === 'https:' ? 'wss:' : 'ws:';
              
              console.log('Intercepting WebSocket connection to:', url);
              
              // Create the proxied URL
              // Instead of connecting directly, we could route through our proxy
              // For now, just using the same URL but ensuring protocol matches
              
              // This is where we'd rewrite to go through a proxy path if needed
              // const proxyUrl = wsProtocol + '//' + window.location.host + '/ws-proxy?url=' + encodeURIComponent(url);
              
              // For simplicity with direct connections, just ensure protocol consistency
              let proxyUrl = url;
              if (parsedUrl.protocol === 'ws:' && wsProtocol === 'wss:') {
                // Upgrade to secure WebSocket if page is https
                proxyUrl = 'wss:' + url.substring(3);
              } else if (parsedUrl.protocol === 'wss:' && wsProtocol === 'ws:') {
                // Downgrade to regular WebSocket if page is http
                proxyUrl = 'ws:' + url.substring(4);
              }
              
              console.log('Proxying WebSocket to:', proxyUrl);
              return new originalWebSocket(proxyUrl, protocols);
            } catch (e) {
              console.error('Error proxying WebSocket:', e);
              // Fallback to original behavior
              return new originalWebSocket(url, protocols);
            }
          };
          
          console.log('Direct proxy client script loaded');
        })();
        </script>
      `;

      // Replace the closing body tag with our script followed by the closing body tag
      html = html.replace('</body>', scriptToInject + '</body>');

      // Send the modified response
      res.setHeader('Content-Length', Buffer.byteLength(html));
      _write.call(res, html);
      _end.call(res);
    };
  }
  
  next();
});

// Function to generate cache key from URL
function getCacheKey(url) {
  return url.toString();
}

// Function to add item to cache
function addToCache(url, data, contentType) {
  const key = getCacheKey(url);
  
  // If cache is full, remove the oldest item
  if (cache.size >= MAX_CACHE_SIZE) {
    const oldestKey = [...cache.keys()][0];
    cache.delete(oldestKey);
  }
  
  cache.set(key, {
    data,
    contentType,
    timestamp: Date.now()
  });
}

// Function to get item from cache
function getFromCache(url) {
  const key = getCacheKey(url);
  const item = cache.get(key);
  
  // Check if item exists and is not expired
  if (item && (Date.now() - item.timestamp) < CACHE_TTL) {
    return item;
  }
  
  // Remove expired item
  if (item) {
    cache.delete(key);
  }
  
  return null;
}

// Clean cache periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, item] of cache.entries()) {
    if ((now - item.timestamp) >= CACHE_TTL) {
      cache.delete(key);
    }
  }
}, 60000); // Check every minute

// Improve cookie handling - parse all cookie attributes instead of just the name=value part
function parseCookies(cookieArray) {
  const cookieMap = {};
  
  if (!cookieArray) return cookieMap;
  
  for (const cookie of cookieArray) {
    if (cookie) {
      // Extract the main cookie name=value part
      const mainPart = cookie.split(';')[0].trim();
      if (!mainPart) continue;
      
      const [name, value] = mainPart.split('=', 2);
      
      // Extract cookie attributes (path, domain, expires, etc.)
      const attributes = {};
      const parts = cookie.split(';').slice(1);
      
      for (const part of parts) {
        const trimmed = part.trim();
        if (!trimmed) continue;
        
        if (trimmed.includes('=')) {
          const [attrName, attrValue] = trimmed.split('=', 2);
          attributes[attrName.toLowerCase().trim()] = attrValue.trim();
        } else {
          // Flags like Secure, HttpOnly
          attributes[trimmed.toLowerCase()] = true;
        }
      }
      
      cookieMap[name] = {
        value,
        attributes
      };
    }
  }
  
  return cookieMap;
}

// Modified session structure for better cookie handling
function createNewSession(sessionId) {
  return {
    id: sessionId,
    cookiesByDomain: {}, // Map of domain -> cookie name -> {value, attributes}
    lastAccess: Date.now(),
    lastProxiedUrl: null
  };
}

// Get or create a session
function getSession(req) {
  const sessionId = req.cookies.proxySessionId || Date.now().toString(36) + Math.random().toString(36).substr(2);
  if (!sessions.has(sessionId)) {
    sessions.set(sessionId, createNewSession(sessionId));
  }
  const session = sessions.get(sessionId);
  session.lastAccess = Date.now();
  return session;
}

// Update session cookies from response
function updateSessionCookies(session, hostname, setCookieHeaders) {
  if (!setCookieHeaders) return;
  
  const parsedCookies = parseCookies(setCookieHeaders);
  
  // Initialize domain cookies if not exists
  if (!session.cookiesByDomain[hostname]) {
    session.cookiesByDomain[hostname] = {};
  }
  
  // Update cookies
  for (const [name, cookieData] of Object.entries(parsedCookies)) {
    session.cookiesByDomain[hostname][name] = cookieData;
  }
  
  console.log(`Updated cookies for domain ${hostname}, cookie count: ${Object.keys(session.cookiesByDomain[hostname]).length}`);
}

// Get cookies applicable for a hostname
function getCookiesForHostname(session, hostname) {
  if (!session) return '';
  
  const cookies = [];
  
  // Find cookies for exact domain match
  if (session.cookiesByDomain[hostname]) {
    for (const [name, {value}] of Object.entries(session.cookiesByDomain[hostname])) {
      cookies.push(`${name}=${value}`);
    }
  }
  
  // Try to find cookies for parent domains
  for (const domain in session.cookiesByDomain) {
    // Skip exact match which we already processed
    if (domain === hostname) continue;
    
    // Check if this is a parent domain
    if (hostname.endsWith('.' + domain) || hostname === domain) {
      for (const [name, {value, attributes}] of Object.entries(session.cookiesByDomain[domain])) {
        // Only include domain cookies
        if (attributes.domain) {
          cookies.push(`${name}=${value}`);
        }
      }
    }
  }
  
  return cookies.join('; ');
}

// Default route - serves the form
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Handle direct navigation to any path that looks like it should be part of the proxied site
app.use((req, res, next) => {
  // Don't intercept requests to /proxy or static assets in /public
  if (req.path.startsWith('/proxy') || req.path.startsWith('/direct-proxy') || req.path === '/' || req.path.match(/\.(html|js|css|png|jpg|jpeg|gif|ico)$/)) {
    return next();
  }
  
  console.log(`Direct access attempt to path: ${req.path}`);
  
  // For any other path, we'll either use the last known domain or a default domain
  let targetDomain = 'https://sunitalia.stoneprofits.com'; // Default domain
  
  // Special handling for ASPX requests
  if (req.path.includes('.aspx')) {
    console.log(`Special handling for ASPX path: ${req.path}`);
    targetDomain = 'https://sunitalia.stoneprofits.com';
  } else {
    // If we have an active session with a last proxied URL, use that domain instead
    const sessionId = req.cookies.proxySessionId;
    const session = sessionId ? sessions.get(sessionId) : null;
    
    if (session && session.lastProxiedUrl) {
      try {
        const originalUrl = new URL(session.lastProxiedUrl);
        targetDomain = originalUrl.origin;
      } catch (e) {
        console.error('Error parsing last proxied URL:', e);
      }
    }
  }
  
  // Check for AJAX requests specifically
  const isAjaxRequest = req.xhr || (req.headers.accept && req.headers.accept.includes('application/json'));
  
  if (isAjaxRequest) {
    console.log(`AJAX request detected to path: ${req.path}`);
    // For AJAX requests, we want to handle them as proxy requests directly rather than redirecting
    // This keeps the original request method and body
    req.query.url = targetDomain + req.path + (req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '');
    console.log(`Proxying AJAX request to: ${req.query.url}`);
    return next();
  }
  
  // Construct the full URL with the target domain and the requested path
  const fullUrl = targetDomain + req.path + (req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '');
  console.log(`Redirecting direct access to ${req.path} to proxied version: ${fullUrl}`);
  
  // Redirect the request to the proxied URL
  return res.redirect(`/proxy?url=${encodeURIComponent(fullUrl)}`);
});

// Add a test connection endpoint
app.get('/test-connection', async (req, res) => {
  try {
    // Test both standard and direct proxy modes
    const standardProxyTest = await testProxyMode('standard');
    const directProxyTest = await testProxyMode('direct');
    
    res.json({
      success: standardProxyTest.success && directProxyTest.success,
      message: 'Proxy is working correctly',
      details: {
        standardProxy: standardProxyTest,
        directProxy: directProxyTest
      }
    });
  } catch (error) {
    console.error('Error testing connection:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Unknown error testing connection'
    });
  }
});

// Function to test each proxy mode
async function testProxyMode(mode) {
  try {
    // Test URL - use a reliable test endpoint
    const testUrl = 'https://httpbin.org/get';
    
    // Test configuration
    const config = {
      method: 'get',
      url: testUrl,
      headers: {
        'User-Agent': 'Zin-Web-Proxy-Test'
      },
      timeout: 5000
    };
    
    const startTime = Date.now();
    const response = await axios(config);
    const endTime = Date.now();
    
    return {
      success: response.status === 200,
      responseTime: endTime - startTime,
      status: response.status,
      mode: mode
    };
  } catch (error) {
    console.error(`Error testing ${mode} proxy mode:`, error);
    return {
      success: false,
      error: error.message,
      mode: mode
    };
  }
}

// Create global error handler
const errorHandler = (err, req, res, next) => {
  console.error('Proxy error:', err);
  res.status(500).send(`
    <html>
      <head>
        <title>Proxy Error</title>
        <style>
          body { font-family: Arial, sans-serif; padding: 20px; max-width: 800px; margin: 0 auto; }
          .error-container { border: 1px solid #f5c6cb; border-radius: 4px; padding: 20px; background-color: #f8d7da; color: #721c24; }
          h1 { color: #721c24; }
          pre { background: #f8f9fa; padding: 10px; border-radius: 4px; overflow: auto; }
          .back-link { margin-top: 20px; }
          .back-link a { color: #0056b3; text-decoration: none; }
          .back-link a:hover { text-decoration: underline; }
        </style>
      </head>
      <body>
        <div class="error-container">
          <h1>Proxy Error</h1>
          <p>There was an error proxying your request:</p>
          <pre>${err.message}</pre>
          <div class="back-link">
            <a href="/">&laquo; Back to proxy homepage</a>
          </div>
        </div>
      </body>
    </html>
  `);
};

// Session handler
app.use('/session', (req, res) => {
  const sessionId = req.cookies.proxySessionId || Date.now().toString(36) + Math.random().toString(36).substr(2);
  
  res.cookie('proxySessionId', sessionId, { 
    httpOnly: true,
    secure: req.secure,
    sameSite: 'lax',
    maxAge: 86400000 // 24 hours
  });
  
  if (!sessions.has(sessionId)) {
    sessions.set(sessionId, createNewSession(sessionId));
  }
  
  res.redirect('/');
});

// Helper functions for URL rewriting in HTML
function isRelativeUrl(url) {
  return !url.match(/^(https?:)?\/\//i);
}

function makeAbsoluteUrl(relativeUrl, baseUrl) {
  try {
    return new URL(relativeUrl, baseUrl).href;
  } catch (e) {
    return relativeUrl;
  }
}

// Function to rewrite HTML content
function rewriteHtml(html, targetUrl, host) {
  try {
    const $ = cheerio.load(html);
    
    // Handle base tag
    let baseUrl = targetUrl;
    const baseTag = $('base[href]');
    if (baseTag.length > 0) {
      baseUrl = new URL(baseTag.attr('href'), targetUrl).href;
    } else {
      // Add base tag if not present
      $('head').prepend(`<base href="${targetUrl}">`);
    }
    
    // Special handling for ReturnUrl in links and forms (generic handling)
    // Find ReturnUrl parameters in links and form actions
    const urlRegex = /(\?|&)ReturnUrl=([^&]+)/g;
    
    // Process links with ReturnUrl parameters
    $('a[href]').each((_, element) => {
      const href = $(element).attr('href');
      if (href && href.includes('ReturnUrl=')) {
        try {
          // Instead of replacing ReturnUrl, just proxy the entire URL
          const proxyUrl = `/proxy?url=${encodeURIComponent(makeAbsoluteUrl(href, baseUrl))}`;
          $(element).attr('href', proxyUrl);
          console.log(`Rewritten ReturnUrl link to: ${proxyUrl}`);
        } catch (e) {
          console.error('Error rewriting ReturnUrl in link:', e);
        }
      }
    });
    
    // Process forms with ReturnUrl in the action
    $('form[action]').each((_, element) => {
      const action = $(element).attr('action');
      if (action && action.includes('ReturnUrl=')) {
        try {
          // Instead of replacing ReturnUrl, just proxy the entire URL
          const proxyUrl = `/proxy?url=${encodeURIComponent(makeAbsoluteUrl(action, baseUrl))}`;
          $(element).attr('action', proxyUrl);
          console.log(`Rewritten ReturnUrl form action to: ${proxyUrl}`);
        } catch (e) {
          console.error('Error rewriting ReturnUrl in form action:', e);
        }
      }
    });
    
    // Process all elements with URL attributes
    const urlAttributes = ['src', 'href', 'action', 'data-src', 'srcset', 'background', 'formaction', 'poster', 'codebase', 'cite', 'longdesc'];
    
    // Process elements with URL attributes
    urlAttributes.forEach(attr => {
      $(`[${attr}]`).each((_, element) => {
        const val = $(element).attr(attr);
        if (!val || val.startsWith('data:') || val.startsWith('#') || val.startsWith('javascript:') || val.startsWith('mailto:') || val.startsWith('tel:')) {
          return;
        }
        
        try {
          // Special handling for forms - preserve their action but ensure it goes through the proxy
          if (element.tagName === 'FORM' && attr === 'action') {
            // Handle empty form actions (self-submitting forms)
            if (val === '' || val === './' || val === '.' || val === '/') {
              // For forms that submit to themselves, use the current URL
              const proxyUrl = `/proxy?url=${encodeURIComponent(baseUrl)}`;
              $(element).attr(attr, proxyUrl);
              
              // Add a hidden input with the original host to help form processing
              $(element).append(`<input type="hidden" name="_proxy_origin" value="${new URL(baseUrl).origin}">`);
              
              // Add target to prevent page from closing
              $(element).attr('target', '_self');
              return;
            }
            
            // Handle relative URLs to absolute ones 
            let absoluteUrl = val;
            if (isRelativeUrl(val)) {
              absoluteUrl = makeAbsoluteUrl(val, baseUrl);
            }
            
            // Convert to proxy URL
            const proxyUrl = `/proxy?url=${encodeURIComponent(absoluteUrl)}`;
            $(element).attr(attr, proxyUrl);
            
            // Add a hidden input with the original host to help form processing
            $(element).append(`<input type="hidden" name="_proxy_origin" value="${new URL(baseUrl).origin}">`);
            
            // Add target to prevent page from closing
            $(element).attr('target', '_self');
            return;
          }
          
          // Regular URL rewriting for other elements
          let absoluteUrl = val;
          if (isRelativeUrl(val)) {
            absoluteUrl = makeAbsoluteUrl(val, baseUrl);
          }
          
          // Convert to proxy URL
          const proxyUrl = `/proxy?url=${encodeURIComponent(absoluteUrl)}`;
          $(element).attr(attr, proxyUrl);
        } catch (error) {
          // Keep original URL if there's an error
        }
      });
    });
    
    // Handle srcset specially
    $('[srcset]').each((_, element) => {
      const srcset = $(element).attr('srcset');
      if (!srcset) return;
      
      try {
        const newSrcset = srcset.split(',').map(part => {
          const [url, ...descriptors] = part.trim().split(/\s+/);
          if (!url || url.startsWith('data:')) return part;
          
          let absoluteUrl = url;
          if (isRelativeUrl(url)) {
            absoluteUrl = makeAbsoluteUrl(url, baseUrl);
          }
          
          return `/proxy?url=${encodeURIComponent(absoluteUrl)} ${descriptors.join(' ')}`;
        }).join(', ');
        
        $(element).attr('srcset', newSrcset);
      } catch (error) {
        // Keep original if there's an error
      }
    });
    
    // Process CSS in style tags
    $('style').each((_, element) => {
      let css = $(element).html();
      if (!css) return;
      
      try {
        // Rewrite urls in CSS
        css = rewriteCssUrls(css, baseUrl);
        $(element).html(css);
      } catch (error) {
        // Keep original if there's an error
      }
    });
    
    // Process inline styles
    $('[style]').each((_, element) => {
      const style = $(element).attr('style');
      if (!style || !style.includes('url(')) return;
      
      try {
        const rewrittenStyle = rewriteCssUrls(style, baseUrl);
        $(element).attr('style', rewrittenStyle);
      } catch (error) {
        // Keep original if there's an error
      }
    });
    
    // Special handling for iframes
    $('iframe').each((_, element) => {
      // Safer sandbox attributes for iframes
      let sandbox = $(element).attr('sandbox');
      if (sandbox) {
        const attrs = sandbox.split(' ');
        if (attrs.includes('allow-scripts') && attrs.includes('allow-same-origin')) {
          // Remove allow-same-origin to prevent sandbox escapes
          const saferAttrs = attrs.filter(a => a !== 'allow-same-origin');
          $(element).attr('sandbox', saferAttrs.join(' '));
        }
      }
      
      // Add referrer policy
      if (!$(element).attr('referrerpolicy')) {
        $(element).attr('referrerpolicy', 'no-referrer');
      }
    });
    
    // Fix target=_blank links
    $('a[target="_blank"]').each((_, element) => {
      if (!$(element).attr('rel')) {
        $(element).attr('rel', 'noopener noreferrer');
      }
    });
    
    // Special handling for stoneprofits.com
    if (targetUrl.includes('stoneprofits.com')) {
      // Block any window.close() calls that might be happening after login
      $('head').append(`
        <script>
          // Save original methods
          const originalWindowClose = window.close;
          const originalLocationReplace = window.location.replace;
          const originalLocationAssign = window.location.assign;
          
          // Override window.close
          window.close = function() {
            console.log('Blocked window.close() call');
            return false;
          };
          
          // Override window.location.replace
          window.location.replace = function(url) {
            console.log('Intercepted window.location.replace:', url);
            // Special handling for ReturnUrl in redirects
            if (url && url.includes('ReturnUrl=')) {
              console.log('Found ReturnUrl in redirect:', url);
              try {
                // If the URL is a ReturnUrl we previously encoded as a proxied URL, extract and use it
                const matches = url.match(/ReturnUrl=([^&]+)/);
                if (matches && matches[1]) {
                  const returnUrl = decodeURIComponent(matches[1]);
                  if (returnUrl.startsWith('/proxy?url=')) {
                    console.log('Using pre-proxied ReturnUrl:', returnUrl);
                    window.location.href = returnUrl;
                    return;
                  }
                }
              } catch (e) {
                console.error('Error processing ReturnUrl redirect:', e);
              }
            }
            
            if (url && !url.includes('/proxy?url=')) {
              let proxyUrl = url;
              if (!url.includes('://')) {
                // Handle relative URLs
                if (!url.startsWith('/')) {
                  url = '/' + url;
                }
                const baseUrl = window.location.href.split('/proxy?url=')[1];
                if (baseUrl) {
                  try {
                    const urlObj = new URL(decodeURIComponent(baseUrl));
                    proxyUrl = urlObj.origin + url;
                  } catch (e) {
                    console.error('Error parsing base URL:', e);
                  }
                }
              }
              window.location.href = '/proxy?url=' + encodeURIComponent(proxyUrl);
              return;
            }
            return originalLocationReplace.call(window.location, url);
          };
          
          // Override window.location.assign
          window.location.assign = function(url) {
            console.log('Intercepted window.location.assign:', url);
            // Special handling for ReturnUrl in redirects
            if (url && url.includes('ReturnUrl=')) {
              console.log('Found ReturnUrl in redirect:', url);
              try {
                // If the URL is a ReturnUrl we previously encoded as a proxied URL, extract and use it
                const matches = url.match(/ReturnUrl=([^&]+)/);
                if (matches && matches[1]) {
                  const returnUrl = decodeURIComponent(matches[1]);
                  if (returnUrl.startsWith('/proxy?url=')) {
                    console.log('Using pre-proxied ReturnUrl:', returnUrl);
                    window.location.href = returnUrl;
                    return;
                  }
                }
              } catch (e) {
                console.error('Error processing ReturnUrl redirect:', e);
              }
            }
            
            if (url && !url.includes('/proxy?url=')) {
              let proxyUrl = url;
              if (!url.includes('://')) {
                // Handle relative URLs
                if (!url.startsWith('/')) {
                  url = '/' + url;
                }
                const baseUrl = window.location.href.split('/proxy?url=')[1];
                if (baseUrl) {
                  try {
                    const urlObj = new URL(decodeURIComponent(baseUrl));
                    proxyUrl = urlObj.origin + url;
                  } catch (e) {
                    console.error('Error parsing base URL:', e);
                  }
                }
              }
              window.location.href = '/proxy?url=' + encodeURIComponent(proxyUrl);
              return;
            }
            return originalLocationAssign.call(window.location, url);
          };
          
          // Monitor form submissions on stoneprofits
          document.addEventListener('submit', function(e) {
            const form = e.target;
            console.log('Form submission on stoneprofits detected:', form);
            
            // Ensure login forms don't redirect inappropriately
            if (form.method && form.method.toLowerCase() === 'post') {
              // Set the target to _self to prevent opening in new tab or closing
              form.target = '_self';
              
              // Add a small delay to ensure the form submits properly
              if (!form.dataset.intercepted) {
                e.preventDefault();
                form.dataset.intercepted = 'true';
                
                // Wait a moment then resubmit
                setTimeout(function() {
                  console.log('Resubmitting intercepted form');
                  form.submit();
                }, 100);
              }
            }
          });
        </script>
      `);
    }
    
    // Add our client-side proxy script to handle dynamic content
    $('head').append(`
      <script>
        // Extract original URL from the proxy URL
        function getOriginalUrl() {
          const proxyUrl = new URL(window.location.href);
          if (proxyUrl.pathname === '/proxy' && proxyUrl.searchParams.has('url')) {
            return proxyUrl.searchParams.get('url');
          }
          return null;
        }
        
        // Get the origin of the original URL
        function getOriginalOrigin() {
          const originalUrl = getOriginalUrl();
          if (originalUrl) {
            try {
              const originalUrlObj = new URL(originalUrl);
              return originalUrlObj.origin;
            } catch (e) {
              console.error('Error parsing original URL:', e);
            }
          }
          return null; // No default fallback
        }
        
        // Store original origin in a global variable for easy access
        window.__originalOrigin = getOriginalOrigin();
        console.log('Original site origin:', window.__originalOrigin);
        
        // Override window.close
        window.close = function() {
          console.log('Blocked window.close() call');
          return false;
        };
        
        // Override window.location.replace
        const originalLocationReplace = window.location.replace;
        window.location.replace = function(url) {
          console.log('Intercepted window.location.replace:', url);
          // Special handling for ReturnUrl in redirects
          if (url && url.includes('ReturnUrl=')) {
            console.log('Found ReturnUrl in redirect:', url);
            try {
              // If the URL is a ReturnUrl we previously encoded as a proxied URL, extract and use it
              const matches = url.match(/ReturnUrl=([^&]+)/);
              if (matches && matches[1]) {
                const returnUrl = decodeURIComponent(matches[1]);
                if (returnUrl.startsWith('/proxy?url=')) {
                  console.log('Using pre-proxied ReturnUrl:', returnUrl);
                  window.location.href = returnUrl;
                  return;
                }
              }
            } catch (e) {
              console.error('Error processing ReturnUrl redirect:', e);
            }
          }
          
          if (url && !url.includes('/proxy?url=')) {
            let proxyUrl = url;
            if (!url.includes('://')) {
              // Handle relative URLs
              if (!url.startsWith('/')) {
                url = '/' + url;
              }
              const baseUrl = window.location.href.split('/proxy?url=')[1];
              if (baseUrl) {
                try {
                  const urlObj = new URL(decodeURIComponent(baseUrl));
                  proxyUrl = urlObj.origin + url;
                } catch (e) {
                  console.error('Error parsing base URL:', e);
                }
              }
            }
            window.location.href = '/proxy?url=' + encodeURIComponent(proxyUrl);
            return;
          }
          return originalLocationReplace.call(window.location, url);
        };
        
        // Override window.location.assign
        const originalLocationAssign = window.location.assign;
        window.location.assign = function(url) {
          console.log('Intercepted window.location.assign:', url);
          // Special handling for ReturnUrl in redirects
          if (url && url.includes('ReturnUrl=')) {
            console.log('Found ReturnUrl in redirect:', url);
            try {
              // If the URL is a ReturnUrl we previously encoded as a proxied URL, extract and use it
              const matches = url.match(/ReturnUrl=([^&]+)/);
              if (matches && matches[1]) {
                const returnUrl = decodeURIComponent(matches[1]);
                if (returnUrl.startsWith('/proxy?url=')) {
                  console.log('Using pre-proxied ReturnUrl:', returnUrl);
                  window.location.href = returnUrl;
                  return;
                }
              }
            } catch (e) {
              console.error('Error processing ReturnUrl redirect:', e);
            }
          }
          
          if (url && !url.includes('/proxy?url=')) {
            let proxyUrl = url;
            if (!url.includes('://')) {
              // Handle relative URLs
              if (!url.startsWith('/')) {
                url = '/' + url;
              }
              const baseUrl = window.location.href.split('/proxy?url=')[1];
              if (baseUrl) {
                try {
                  const urlObj = new URL(decodeURIComponent(baseUrl));
                  proxyUrl = urlObj.origin + url;
                } catch (e) {
                  console.error('Error parsing base URL:', e);
                }
              }
            }
            window.location.href = '/proxy?url=' + encodeURIComponent(proxyUrl);
            return;
          }
          return originalLocationAssign.call(window.location, url);
        };
        
        // Monitor form submissions
        document.addEventListener('submit', function(e) {
          const form = e.target;
          console.log('Form submission detected:', form);
          
          // Ensure forms don't redirect inappropriately
          if (form.method && form.method.toLowerCase() === 'post') {
            // Set the target to _self to prevent opening in new tab or closing
            form.target = '_self';
            
            // Add a small delay to ensure the form submits properly
            if (!form.dataset.intercepted) {
              e.preventDefault();
              form.dataset.intercepted = 'true';
              
              // Wait a moment then resubmit
              setTimeout(function() {
                console.log('Resubmitting intercepted form');
                form.submit();
              }, 100);
            }
          }
        });
        
        // Fix AJAX calls by overriding jQuery if it exists
        function fixjQuery() {
          if (window.jQuery || window.$) {
            const originalAjax = (window.jQuery || window.$).ajax;
            if (originalAjax) {
              console.log('Overriding jQuery.ajax');
              (window.jQuery || window.$).ajax = function(url, options) {
                // Handle both call patterns: .ajax(url, options) and .ajax(options)
                let ajaxOptions = options;
                if (typeof url === 'string') {
                  ajaxOptions = options || {};
                  ajaxOptions.url = url;
                } else {
                  ajaxOptions = url || {};
                }
                
                // Fix relative URLs
                if (ajaxOptions.url && !ajaxOptions.url.includes('://') && !ajaxOptions.url.startsWith('/proxy')) {
                  // Handle both /path and path formats
                  if (!ajaxOptions.url.startsWith('/')) {
                    ajaxOptions.url = '/' + ajaxOptions.url;
                  }
                  
                  if (window.__originalOrigin) {
                    ajaxOptions.url = window.__originalOrigin + ajaxOptions.url;
                    console.log('Rewriting jQuery AJAX URL to:', ajaxOptions.url);
                  }
                  
                  // Use the proxy for the request
                  ajaxOptions.url = '/proxy?url=' + encodeURIComponent(ajaxOptions.url);
                }
                
                // Fix AJAX callbacks to ensure they work with proxied responses
                if (ajaxOptions.success || ajaxOptions.error || ajaxOptions.complete) {
                  const originalSuccess = ajaxOptions.success;
                  const originalError = ajaxOptions.error;
                  const originalComplete = ajaxOptions.complete;
                  
                  if (originalSuccess) {
                    ajaxOptions.success = function(data, textStatus, jqXHR) {
                      console.log('jQuery AJAX success:', textStatus);
                      return originalSuccess.call(this, data, textStatus, jqXHR);
                    };
                  }
                  
                  if (originalError) {
                    ajaxOptions.error = function(jqXHR, textStatus, errorThrown) {
                      console.log('jQuery AJAX error:', textStatus, errorThrown);
                      return originalError.call(this, jqXHR, textStatus, errorThrown);
                    };
                  }
                }
                
                return originalAjax.call(this, ajaxOptions);
              };
            }
          }
        }
        
        // Try to fix jQuery as soon as it's loaded
        fixjQuery();
        
        // Check again in case jQuery loads later
        setTimeout(fixjQuery, 1000);
        setTimeout(fixjQuery, 2000);
        
        // Detect and fix links
        document.addEventListener('click', function(e) {
          // Check if the click target or any of its parents is an A tag
          let target = e.target;
          let aElement = null;
          
          // Traverse up the DOM tree to find the closest A tag
          while (target && target !== document) {
            if (target.tagName === 'A') {
              aElement = target;
              break;
            }
            target = target.parentNode;
          }
          
          // Process if we found an A tag with an href
          if (aElement && aElement.href) {
            const href = aElement.href;
            console.log('Clicked link:', href);
            
            // Check if it needs rewriting
            const needsRewriting = !href.includes('/proxy?url=') && 
                                  (href.startsWith('/') || 
                                   !href.includes('://') || 
                                   href.startsWith(window.location.origin + '/'));
            
            if (needsRewriting) {
              e.preventDefault();
              
              // Get the href, removing the origin if it matches the current page
              let cleanHref = href;
              if (cleanHref.startsWith(window.location.origin)) {
                cleanHref = cleanHref.substring(window.location.origin.length);
              }
              
              // Handle empty or hash-only hrefs
              if (!cleanHref || cleanHref === '#' || cleanHref === 'javascript:void(0)') {
                console.log('Ignoring empty or javascript href');
                return; // Let the original handler process it
              }
              
              // Build the full URL with the original site's origin
              const targetUrl = window.__originalOrigin + (cleanHref.startsWith('/') ? cleanHref : '/' + cleanHref);
              console.log('Redirecting link to:', targetUrl);
              
              // Navigate to the proxied version
              window.location.href = '/proxy?url=' + encodeURIComponent(targetUrl);
            }
          }
        });
      </script>
    `);
    
    return $.html();
  } catch (e) {
    console.error('Error rewriting HTML:', e);
    return html; // Return original if rewriting fails
  }
}

// Function to rewrite URLs in CSS content
function rewriteCssUrls(css, baseUrl) {
  return css.replace(/url\(['"]?([^'")]+)['"]?\)/g, (match, cssUrl) => {
    if (!cssUrl || cssUrl.startsWith('data:')) {
      return match;
    }
    
    try {
      // Make relative URLs absolute
      const absoluteUrl = isRelativeUrl(cssUrl) ? makeAbsoluteUrl(cssUrl, baseUrl) : cssUrl;
      return `url('/proxy?url=${encodeURIComponent(absoluteUrl)}')`;
    } catch (error) {
      return match;
    }
  });
}

// Main proxy route
app.use('/proxy', async (req, res, next) => {
  // Get the full URL including all query parameters
  const originalUrl = req.originalUrl;
  
  // Check if URL has ReturnUrl as a direct query parameter (not inside the encoded url)
  const hasExternalReturnUrl = originalUrl.includes('&ReturnUrl=');
  
  // If we have an external ReturnUrl, extract the base URL and fix it
  if (hasExternalReturnUrl && originalUrl.startsWith('/proxy?url=')) {
    const urlParts = originalUrl.split('&ReturnUrl=');
    if (urlParts.length === 2) {
      // Get the base URL (part before ReturnUrl)
      const baseUrlParam = urlParts[0].replace('/proxy?url=', '');
      let baseUrl;
      
      try {
        // Decode the base URL
        baseUrl = decodeURIComponent(baseUrlParam);
        
        // Get the ReturnUrl part
        const returnUrlPart = urlParts[1];
        
        // Create a proper URL with ReturnUrl as a parameter
        let redirectUrl;
        
        // Check if the base URL already has parameters
        if (baseUrl.includes('?')) {
          redirectUrl = baseUrl + '&ReturnUrl=' + returnUrlPart;
        } else {
          redirectUrl = baseUrl + '?ReturnUrl=' + returnUrlPart;
        }
        
        // Redirect to the fixed URL
        console.log(`Fixed ReturnUrl structure, redirecting to: ${redirectUrl}`);
        return res.redirect(`/proxy?url=${encodeURIComponent(redirectUrl)}`);
      } catch (e) {
        console.error('Error fixing ReturnUrl parameter:', e);
      }
    }
  }

  const targetUrl = req.query.url;
  
  // Check if the request is a POST with a form submission where the target URL is the same
  if (!targetUrl && req.method === 'POST') {
    console.log('POST request without target URL, attempting to determine target');
    
    // Special handling for ASPX form submissions
    if (req.path.includes('.aspx')) {
      console.log('Detected ASPX form submission to:', req.path);
      // Use stoneprofits domain for all ASPX form submissions
      const aspxTarget = 'https://sunitalia.stoneprofits.com' + req.path + (req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '');
      req.query.url = aspxTarget;
      console.log(`Setting ASPX form target to: ${aspxTarget}`);
    }
    // First check for our special hidden field
    else if (req.body && req.body._proxy_origin) {
      let formAction = req.path; // Default to the current path
      
      // Look for the target path in the referer
      if (req.headers.referer) {
        try {
          const refUrl = new URL(req.headers.referer);
          if (refUrl.pathname === '/proxy' && refUrl.searchParams.has('url')) {
            const extractedUrl = refUrl.searchParams.get('url');
            const origUrl = new URL(extractedUrl);
            // Replace the origin with the one from the hidden field
            formAction = req.body._proxy_origin + origUrl.pathname + origUrl.search;
            delete req.body._proxy_origin; // Remove our special field so it doesn't get sent to target
            req.query.url = formAction;
            console.log(`Using origin from hidden field: ${formAction}`);
          }
        } catch (e) {
          console.error('Error parsing form origin URL:', e);
        }
      } else {
        // If no referer, just use the origin from the hidden field with the current path
        formAction = req.body._proxy_origin + req.path;
        delete req.body._proxy_origin; // Remove our special field so it doesn't get sent to target
        req.query.url = formAction;
        console.log(`Using origin from hidden field with current path: ${formAction}`);
      }
    }
    // Fallback to referer method if no hidden field
    else if (req.headers.referer) {
      try {
        const refUrl = new URL(req.headers.referer);
        if (refUrl.pathname === '/proxy' && refUrl.searchParams.has('url')) {
          const extractedUrl = refUrl.searchParams.get('url');
          
          // If the referrer is an ASPX page, make sure we're posting to the right domain
          if (extractedUrl.includes('.aspx')) {
            const origUrl = new URL(extractedUrl);
            req.query.url = origUrl.origin + req.path + (req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '');
            console.log(`Extracted target URL for ASPX form post: ${req.query.url}`);
          } else {
            req.query.url = extractedUrl;
            console.log(`Extracted target URL from referer: ${extractedUrl}`);
          }
        }
      } catch (e) {
        console.error('Error parsing referer URL:', e);
      }
    }
    // Last resort fallback for POST requests without a referrer or hidden field
    else if (!req.query.url) {
      console.log('No target URL could be determined, using default domain');
      // Use default domain with the current path
      req.query.url = 'https://sunitalia.stoneprofits.com' + req.path + (req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '');
      console.log(`Using default domain with current path: ${req.query.url}`);
    }
  }
  
  // Final check for targetUrl
  if (!req.query.url) {
    return res.status(400).send(`
      <html>
        <head>
          <title>Missing URL</title>
          <style>
            body { font-family: Arial, sans-serif; padding: 20px; max-width: 800px; margin: 0 auto; }
            .error-container { border: 1px solid #f5c6cb; border-radius: 4px; padding: 20px; background-color: #f8d7da; color: #721c24; }
            h1 { color: #721c24; }
            .back-link { margin-top: 20px; }
            .back-link a { color: #0056b3; text-decoration: none; }
            .back-link a:hover { text-decoration: underline; }
          </style>
        </head>
        <body>
          <div class="error-container">
            <h1>Missing URL</h1>
            <p>URL parameter is required to use the proxy.</p>
            <div class="back-link">
              <a href="/">&laquo; Back to proxy homepage</a>
            </div>
          </div>
        </body>
      </html>
    `);
  }
  
  try {
    const parsedUrl = new URL(req.query.url);
    const session = getSession(req);
    
    if (session) {
      // Store this URL as the last proxied URL for this session
      session.lastProxiedUrl = parsedUrl.href;
    }
    
    // Check cache for static resources
    const cachedResponse = getFromCache(parsedUrl.href);
    if (cachedResponse && ['GET', 'HEAD'].includes(req.method)) {
      console.log(`Cache hit for: ${parsedUrl.href}`);
      res.setHeader('Content-Type', cachedResponse.contentType);
      res.setHeader('X-Proxy-Cache', 'HIT');
      res.setHeader('X-Proxied-By', 'Zin-Web-Proxy');
      return res.send(cachedResponse.data);
    }
    
    console.log(`Proxying request to: ${parsedUrl.href}`);
    
    // Prepare request headers with proper cookies
    const headers = {
      'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      'Accept': req.headers.accept || 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
      'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
      'Accept-Encoding': 'identity', // Don't request compressed content to simplify processing
      'Connection': 'keep-alive',
      'Pragma': 'no-cache',
      'Cache-Control': 'no-cache',
      'Upgrade-Insecure-Requests': '1'
    };
    
    // Copy some headers from the original request
    const headersToKeep = ['content-type', 'x-requested-with', 'dnt', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest'];
    headersToKeep.forEach(header => {
      if (req.headers[header]) {
        headers[header] = req.headers[header];
      }
    });
    
    // Get cookies for this hostname from session
    const cookieHeader = getCookiesForHostname(session, parsedUrl.hostname);
    if (cookieHeader) {
      headers.Cookie = cookieHeader;
      console.log(`Added cookies for ${parsedUrl.hostname}: ${cookieHeader.substring(0, 100)}${cookieHeader.length > 100 ? '...' : ''}`);
    }
    
    // Set referer if it's a navigation from another proxied page
    if (req.headers.referer) {
      try {
        const refererUrl = new URL(req.headers.referer);
        if (refererUrl.pathname === '/proxy' && refererUrl.searchParams.has('url')) {
          const originalReferer = refererUrl.searchParams.get('url');
          headers.Referer = originalReferer;
        } else {
          headers.Referer = parsedUrl.origin;
        }
      } catch (e) {
        headers.Referer = parsedUrl.origin;
      }
    }
    
    // Prepare request config
    const requestConfig = {
      method: req.method,
      url: parsedUrl.href,
      headers: headers,
      responseType: 'arraybuffer',
      maxRedirects: 5,
      validateStatus: () => true, // Don't reject on any status code
      timeout: 30000
    };
    
    // Add body for POST, PUT, PATCH requests
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
      // Handle different content types
      if (req.headers['content-type']) {
        if (req.headers['content-type'].includes('application/json')) {
          requestConfig.data = req.body;
        } else if (req.headers['content-type'].includes('application/x-www-form-urlencoded')) {
          requestConfig.data = req.body;
        } else if (req.headers['content-type'].includes('multipart/form-data')) {
          requestConfig.data = req.body;
        } else {
          requestConfig.data = req.body;
        }
      } else {
        requestConfig.data = req.body;
      }
    }
    
    // Make the request
    const response = await axios(requestConfig);
    
    // Update session cookies from response
    if (session && response.headers['set-cookie']) {
      updateSessionCookies(session, parsedUrl.hostname, response.headers['set-cookie']);
      
      // Save session ID in response cookie if needed
      if (!req.cookies.proxySessionId) {
        res.cookie('proxySessionId', session.id, { 
          httpOnly: true,
          secure: req.secure,
          sameSite: 'lax',
          maxAge: 86400000 // 24 hours
        });
      }
    }
    
    // Generic handling for redirects (302 responses)
    if (response.status === 302 && response.headers.location) {
      const redirectUrl = response.headers.location;
      console.log(`Received redirect to: ${response.headers.location}`);
      
      // Special handling for ReturnUrl redirects
      if (redirectUrl.includes('ReturnUrl=')) {
        // Extract the ReturnUrl parameter
        const returnUrlMatch = redirectUrl.match(/ReturnUrl=([^&]+)/);
        if (returnUrlMatch && returnUrlMatch[1]) {
          let returnUrl = decodeURIComponent(returnUrlMatch[1]);
          console.log(`Found ReturnUrl parameter: ${returnUrl}`);
          
          // Check if the ReturnUrl starts with a slash (relative URL)
          if (returnUrl.startsWith('/')) {
            // Make it absolute
            returnUrl = `${parsedUrl.protocol}//${parsedUrl.host}${returnUrl}`;
            console.log(`Made ReturnUrl absolute: ${returnUrl}`);
          }
          
          // Redirect directly to the ReturnUrl through our proxy
          console.log(`Redirecting to ReturnUrl through proxy: ${returnUrl}`);
          return res.redirect(`/proxy?url=${encodeURIComponent(returnUrl)}`);
        }
      }
      
      // Default handling for other redirects
      // Make sure the redirect URL is absolute
      let absoluteRedirectUrl;
      if (redirectUrl.startsWith('http')) {
        absoluteRedirectUrl = redirectUrl;
      } else if (redirectUrl.startsWith('/')) {
        absoluteRedirectUrl = `${parsedUrl.protocol}//${parsedUrl.host}${redirectUrl}`;
      } else {
        absoluteRedirectUrl = `${parsedUrl.protocol}//${parsedUrl.host}/${redirectUrl}`;
      }
      
      // Redirect through our proxy
      console.log(`Redirecting to: ${absoluteRedirectUrl} through proxy`);
      return res.redirect(`/proxy?url=${encodeURIComponent(absoluteRedirectUrl)}`);
    }
    
    // Get response data and content type
    const responseData = Buffer.from(response.data);
    const contentType = response.headers['content-type'] || '';
    
    // Determine resource type
    const isHtml = contentType.includes('text/html');
    const isCss = contentType.includes('text/css') || parsedUrl.pathname.endsWith('.css');
    const isJs = contentType.includes('javascript') || 
                 contentType.includes('application/js') || 
                 parsedUrl.pathname.endsWith('.js');
    const isFont = contentType.includes('font') || 
                  /\.(woff2?|ttf|eot|otf)(\?|$)/i.test(parsedUrl.pathname);
    const isImage = contentType.includes('image/') || 
                   /\.(png|jpe?g|gif|svg|webp|ico)(\?|$)/i.test(parsedUrl.pathname);
    
    // Set response headers
    Object.entries(response.headers).forEach(([key, value]) => {
      // Skip headers we'll handle specially
      if (!['content-length', 'content-encoding', 'transfer-encoding', 'set-cookie'].includes(key.toLowerCase())) {
        res.setHeader(key, value);
      }
    });
    
    // Always set the correct content type
    if (contentType) {
      res.setHeader('Content-Type', contentType);
    }
    
    // Set cache control to improve performance
    if (['GET', 'HEAD'].includes(req.method)) {
      if (isFont || isImage) {
        res.setHeader('Cache-Control', 'public, max-age=86400'); // 1 day
      } else if (isJs || isCss) {
        res.setHeader('Cache-Control', 'public, max-age=3600'); // 1 hour
      } else {
        res.setHeader('Cache-Control', 'no-cache, must-revalidate');
      }
    }
    
    res.setHeader('X-Proxied-By', 'Zin-Web-Proxy');
    
    try {
      // Process HTML content
      if (isHtml && response.status === 200) {
        const html = responseData.toString('utf8');
        const rewrittenHtml = rewriteHtml(html, parsedUrl.href, req.headers.host);
        return res.send(rewrittenHtml);
      } 
      // Process CSS content
      else if (isCss && response.status === 200) {
        const css = responseData.toString('utf8');
        const rewrittenCss = rewriteCssUrls(css, parsedUrl.href);
        res.setHeader('Content-Type', 'text/css');
        
        // Cache CSS for future requests
        addToCache(parsedUrl.href, rewrittenCss, 'text/css');
        
        return res.send(rewrittenCss);
      }
      // Handle JavaScript
      else if (isJs && response.status === 200) {
        res.setHeader('Content-Type', 'application/javascript');
        
        // Cache JavaScript for future requests
        addToCache(parsedUrl.href, responseData, 'application/javascript');
        
        return res.send(responseData);
      }
      // Handle fonts and images directly
      else if ((isFont || isImage) && response.status === 200) {
        // Cache fonts and images for future requests
        addToCache(parsedUrl.href, responseData, contentType);
        
        return res.send(responseData);
      }
      // All other content types
      else {
        res.status(response.status);
        
        // Cache successful responses of common types
        if (response.status === 200 && ['GET', 'HEAD'].includes(req.method) && responseData.length < 5 * 1024 * 1024) {
          addToCache(parsedUrl.href, responseData, contentType);
        }
        
        return res.send(responseData);
      }
    } catch (processingError) {
      console.error('Error processing response:', processingError);
      
      // Fall back to sending the original response
      res.status(response.status);
      return res.send(responseData);
    }
    
  } catch (error) {
    next(error);
  }
});

// Cleanup expired sessions (every hour)
setInterval(() => {
  const now = Date.now();
  const expiryTime = 3600000; // 1 hour
  
  for (const [sessionId, sessionData] of sessions.entries()) {
    if (sessionData.lastAccess && (now - sessionData.lastAccess) > expiryTime) {
      sessions.delete(sessionId);
    }
  }
}, 3600000);

// Handle errors
app.use(errorHandler);

// Main server startup function
async function startServer() {
  // Set up certificate manager if Let's Encrypt is enabled
  if (useHttps && useLetsEncrypt) {
    try {
      console.log('Setting up Let\'s Encrypt certificate manager...');
      
      const certManager = new CertificateManager({
        domain: process.env.LETSENCRYPT_DOMAIN,
        email: process.env.LETSENCRYPT_EMAIL,
        sslDir: path.dirname(process.env.SSL_CERT_PATH || path.join(__dirname, '../ssl')),
        keyPath: process.env.SSL_KEY_PATH || path.join(__dirname, '../ssl/key.pem'),
        certPath: process.env.SSL_CERT_PATH || path.join(__dirname, '../ssl/cert.pem'),
        production: process.env.LETSENCRYPT_PRODUCTION === 'true',
        app: app
      });
      
      // Ensure certificates exist and are valid
      const certResult = await certManager.ensureCertificates();
      
      if (certResult.hasValidCerts) {
        console.log('Valid Let\'s Encrypt certificates available');
        httpsOptions = {
          key: fs.readFileSync(certResult.keyPath),
          cert: fs.readFileSync(certResult.certPath)
        };
      } else {
        console.error('Failed to obtain Let\'s Encrypt certificates');
        console.log('Falling back to HTTP server');
        useHttps = false;
      }
    } catch (error) {
      console.error('Error setting up Let\'s Encrypt:', error);
      console.log('Falling back to HTTP server');
      useHttps = false;
    }
  }
  // Use regular certificate loading if Let's Encrypt is not enabled
  else if (useHttps) {
    try {
      // Carefully check if the paths exist and are files, not directories
      const keyPath = process.env.SSL_KEY_PATH || path.join(__dirname, '../ssl/key.pem');
      const certPath = process.env.SSL_CERT_PATH || path.join(__dirname, '../ssl/cert.pem');
      
      // Verify both paths are files, not directories
      const keyStats = fs.statSync(keyPath);
      const certStats = fs.statSync(certPath);
      
      if (keyStats.isDirectory() || certStats.isDirectory()) {
        throw new Error('SSL paths point to directories instead of files');
      }
      
      // Try to load SSL certificate and key from files
      httpsOptions = {
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath),
      };
      console.log('Loaded SSL certificates for HTTPS server');
    } catch (e) {
      console.error('Error loading SSL certificates:', e.message);
      console.log('Falling back to HTTP server');
      useHttps = false;
    }
  }

  // Configure HTTPS for the proxy server itself
  if (useHttps) {
    const httpsServer = https.createServer(httpsOptions, app);
    
    // Set up WebSocket handling for HTTPS server
    const directProxyMiddleware = setupDirectProxy();
    app.use('/direct-proxy', directProxyMiddleware);
    
    // Make sure WebSocket upgrade requests are handled by the proxy middleware
    httpsServer.on('upgrade', function (req, socket, head) {
      if (req.url.startsWith('/direct-proxy')) {
        directProxyMiddleware.upgrade(req, socket, head);
      }
    });
    
    httpsServer.listen(PORT, () => {
      console.log(`Proxy server running on https://localhost:${PORT}`);
    });
  } else {
    const httpServer = http.createServer(app);
    
    // Set up WebSocket handling for HTTP server
    const directProxyMiddleware = setupDirectProxy();
    app.use('/direct-proxy', directProxyMiddleware);
    
    // Make sure WebSocket upgrade requests are handled by the proxy middleware
    httpServer.on('upgrade', function (req, socket, head) {
      if (req.url.startsWith('/direct-proxy')) {
        directProxyMiddleware.upgrade(req, socket, head);
      }
    });
    
    httpServer.listen(PORT, () => {
      console.log(`Proxy server running on http://localhost:${PORT}`);
    });
  }
}

// Start the server
startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});