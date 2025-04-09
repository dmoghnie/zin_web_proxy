/**
 * Certificate Manager for Let's Encrypt
 * Automatically manages SSL certificates using Let's Encrypt
 */

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const acme = require('acme-client');
const express = require('express');

const execAsync = promisify(exec);
const mkdir = promisify(fs.mkdir);
const writeFile = promisify(fs.writeFile);
const readFile = promisify(fs.readFile);
const access = promisify(fs.access);

class CertificateManager {
  constructor(options = {}) {
    this.domain = options.domain;
    this.email = options.email;
    this.sslDir = options.sslDir || path.join(process.cwd(), 'ssl');
    this.keyPath = options.keyPath || path.join(this.sslDir, 'key.pem');
    this.certPath = options.certPath || path.join(this.sslDir, 'cert.pem');
    this.production = options.production !== false; // Use production by default
    this.logger = options.logger || console;
    this.port = options.port || 80; // Port for HTTP-01 challenge
    
    // Used for HTTP-01 challenge server
    this.app = options.app;
    this.challengeDir = path.join(this.sslDir, 'acme-challenge');
    // Store active challenges
    this.activeTokens = {};
  }

  /**
   * Initialize certificate manager
   */
  async init() {
    try {
      // Create SSL directory if it doesn't exist
      await mkdir(this.sslDir, { recursive: true });
      await mkdir(this.challengeDir, { recursive: true });
      
      this.logger.log(`Certificate manager initialized for domain: ${this.domain}`);
      return true;
    } catch (error) {
      this.logger.error('Failed to initialize certificate manager:', error);
      return false;
    }
  }

  /**
   * Check if certificates exist and are valid
   */
  async checkCertificates() {
    try {
      // Check if cert files exist
      await access(this.keyPath, fs.constants.F_OK);
      await access(this.certPath, fs.constants.F_OK);
      
      // Check certificate expiration
      const certData = await readFile(this.certPath, 'utf8');
      const cert = new acme.crypto.Certificate(certData);
      
      // Parse the certificate to get expiration date
      if (!cert.isExpired()) {
        this.logger.log('Valid certificates found');
        return true;
      } else {
        this.logger.log('Certificate is expired, will request new one');
        return false;
      }
    } catch (error) {
      this.logger.log('No valid certificates found:', error.message);
      return false;
    }
  }

  /**
   * Setup HTTP-01 challenge middleware
   */
  setupChallengeMiddleware() {
    if (!this.app) {
      throw new Error('Express app not provided for challenge middleware');
    }
    
    // Serve ACME challenge files - This must have highest priority!
    this.app.use('/.well-known/acme-challenge', (req, res, next) => {
      const challengeToken = req.path.split('/').pop();
      
      // First check if we have this token in memory (for immediate challenges)
      if (this.activeTokens[challengeToken]) {
        this.logger.log(`Serving token from memory: ${challengeToken}`);
        res.set('Content-Type', 'text/plain');
        return res.send(this.activeTokens[challengeToken]);
      }
      
      // If not in memory, try to read from file
      const challengePath = path.join(this.challengeDir, challengeToken);
      
      fs.readFile(challengePath, 'utf8', (err, data) => {
        if (err) {
          this.logger.error(`Error reading challenge token: ${err.message}`);
          return next();
        }
        res.set('Content-Type', 'text/plain');
        res.send(data);
      });
    });
    
    // For debugging - list all available challenge tokens
    this.app.get('/.well-known/acme-challenge-debug', (req, res) => {
      fs.readdir(this.challengeDir, (err, files) => {
        if (err) {
          return res.status(500).send(`Error reading challenge directory: ${err.message}`);
        }
        
        // List all tokens
        const memoryTokens = Object.keys(this.activeTokens);
        res.send({
          memoryTokens,
          fileTokens: files,
          domain: this.domain,
          challengeDir: this.challengeDir
        });
      });
    });
    
    this.logger.log('HTTP-01 challenge middleware set up');
  }
  
  /**
   * Set up a standalone HTTP server for ACME challenge if needed
   */
  setupStandaloneServer() {
    // Only start if we're using port 80 and don't have a custom app
    if (this.port === 80 && !this.app) {
      this.logger.log('Setting up standalone HTTP server for ACME challenges on port 80');
      
      const app = express();
      
      // Serve ACME challenge files
      app.use('/.well-known/acme-challenge', (req, res) => {
        const challengeToken = req.path.split('/').pop();
        
        // First check if we have this token in memory
        if (this.activeTokens[challengeToken]) {
          this.logger.log(`Serving token from memory: ${challengeToken}`);
          res.set('Content-Type', 'text/plain');
          return res.send(this.activeTokens[challengeToken]);
        }
        
        // If not in memory, try to read from file
        const challengePath = path.join(this.challengeDir, challengeToken);
        
        fs.readFile(challengePath, 'utf8', (err, data) => {
          if (err) {
            this.logger.error(`Error reading challenge token: ${err.message}`);
            return res.status(404).send('Challenge not found');
          }
          res.set('Content-Type', 'text/plain');
          res.send(data);
        });
      });
      
      // Default response for all other requests
      app.use((req, res) => {
        res.send('ACME Challenge Server');
      });
      
      // Store the HTTP server so we can close it later
      this.httpServer = app.listen(80, () => {
        this.logger.log('ACME Challenge server is running on port 80');
      });
    }
  }
  
  /**
   * Request new certificates using Let's Encrypt
   */
  async requestCertificates() {
    if (!this.domain || !this.email) {
      throw new Error('Domain and email are required for certificate request');
    }
    
    // Start standalone server if needed
    this.setupStandaloneServer();
    
    this.logger.log(`Requesting new certificates for ${this.domain}`);
    
    try {
      // Create ACME client
      const client = new acme.Client({
        directoryUrl: this.production
          ? acme.directory.letsencrypt.production
          : acme.directory.letsencrypt.staging,
        accountKey: await acme.crypto.createPrivateKey()
      });
      
      // Create a private key for the certificate
      const privateKey = await acme.crypto.createPrivateKey();
      
      // Initialize account with email
      await client.createAccount({
        termsOfServiceAgreed: true,
        contact: [`mailto:${this.email}`]
      });
      
      // Handle HTTP-01 challenge
      const challengeCreateFn = async (authz, challenge, keyAuthorization) => {
        // Store challenge both in memory and in file for redundancy
        this.activeTokens[challenge.token] = keyAuthorization;
        
        const challengeFile = path.join(this.challengeDir, challenge.token);
        await writeFile(challengeFile, keyAuthorization);
        this.logger.log(`Created challenge file at: ${challengeFile}`);
        
        // For debugging: check if the challenge file is accessible
        try {
          // Try to access it via local filesystem
          await access(challengeFile, fs.constants.R_OK);
          this.logger.log(`Challenge file is readable: ${challengeFile}`);
          
          // If we're in development mode, we could curl the challenge URL directly
          // This could be enabled for debugging but requires curl to be installed
          if (!this.production) {
            try {
              await execAsync(`curl -s http://${this.domain}/.well-known/acme-challenge/${challenge.token}`);
              this.logger.log(`Successfully accessed challenge via HTTP request`);
            } catch (e) {
              this.logger.log(`Warning: Could not access challenge via HTTP: ${e.message}`);
            }
          }
        } catch (e) {
          this.logger.error(`Warning: Challenge file might not be accessible: ${e.message}`);
        }
      };
      
      const challengeRemoveFn = async (authz, challenge) => {
        // Remove from memory
        delete this.activeTokens[challenge.token];
        
        // Remove from filesystem
        const challengeFile = path.join(this.challengeDir, challenge.token);
        try {
          await promisify(fs.unlink)(challengeFile);
          this.logger.log(`Removed challenge file: ${challengeFile}`);
        } catch (error) {
          this.logger.error(`Error removing challenge file: ${error.message}`);
        }
      };
      
      // Request certificate
      const [key, csr] = await acme.crypto.createCsr({
        commonName: this.domain,
        altNames: [this.domain]
      });
      
      // Get certificate
      this.logger.log(`Submitting certificate request for ${this.domain}...`);
      const certificate = await client.auto({
        csr,
        email: this.email,
        termsOfServiceAgreed: true,
        challengeCreateFn,
        challengeRemoveFn,
        challengePriority: ['http-01']
      });
      
      this.logger.log(`Certificate request successful! Saving certificates...`);
      
      // Save certificate and key
      await writeFile(this.keyPath, key);
      await writeFile(this.certPath, certificate);
      
      this.logger.log(`Certificates successfully saved to ${this.sslDir}`);
      
      // Close standalone server if we created one
      if (this.httpServer) {
        this.httpServer.close();
        this.logger.log('Closed standalone ACME challenge server');
      }
      
      return true;
    } catch (error) {
      this.logger.error('Error requesting certificates:', error);
      
      // Close standalone server if we created one
      if (this.httpServer) {
        this.httpServer.close();
        this.logger.log('Closed standalone ACME challenge server');
      }
      
      return false;
    }
  }
  
  /**
   * Ensure certificates exist and are valid, requesting new ones if needed
   */
  async ensureCertificates() {
    try {
      // Initialize
      await this.init();
      
      // Set up challenge middleware
      this.setupChallengeMiddleware();
      
      // Check if we have valid certificates
      const hasValidCerts = await this.checkCertificates();
      
      // If not, request new ones
      if (!hasValidCerts) {
        await this.requestCertificates();
      }
      
      // Return certificate paths
      return {
        keyPath: this.keyPath,
        certPath: this.certPath,
        hasValidCerts: await this.checkCertificates()
      };
    } catch (error) {
      this.logger.error('Failed to ensure certificates:', error);
      throw error;
    }
  }
}

module.exports = CertificateManager; 