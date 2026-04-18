const crypto = require('crypto');

// JWT Utilities
function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64UrlDecode(str) {
  // Add padding
  const padding = 4 - (str.length % 4);
  if (padding !== 4) {
    str += '='.repeat(padding);
  }
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();
}

function signHMAC(data, secret, algorithm) {
  const hashAlgo = algorithm.replace('HS', 'SHA');
  return crypto.createHmac(hashAlgo, secret).update(data).digest('base64url');
}

function signRSA(data, privateKey, algorithm) {
  const hashAlgo = algorithm.replace('RS', 'SHA');
  return crypto.createSign(hashAlgo).update(data).sign(privateKey, 'base64url');
}

function signECDSA(data, privateKey, algorithm) {
  const hashAlgo = algorithm.replace('ES', 'SHA');
  return crypto.createSign(hashAlgo).update(data).sign(privateKey, 'base64url');
}

function verifyHMAC(data, signature, secret, algorithm) {
  const hashAlgo = algorithm.replace('HS', 'SHA');
  const expected = crypto.createHmac(hashAlgo, secret).update(data).digest('base64url');
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

function verifyRSA(data, signature, publicKey, algorithm) {
  const hashAlgo = algorithm.replace('RS', 'SHA');
  return crypto.createVerify(hashAlgo).update(data).verify(publicKey, signature, 'base64url');
}

function verifyECDSA(data, signature, publicKey, algorithm) {
  const hashAlgo = algorithm.replace('ES', 'SHA');
  return crypto.createVerify(hashAlgo).update(data).verify(publicKey, signature, 'base64url');
}

module.exports = async (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-License-Key');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed', allowed: ['POST'] });
  }

  try {
    const { action, algorithm = 'HS256', payload, secret, privateKey, publicKey, token } = req.body;

    if (!action) {
      return res.status(400).json({ error: 'Missing required field: action' });
    }

    const supportedAlgorithms = ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];

    switch (action) {
      case 'generate': {
        if (!payload) {
          return res.status(400).json({ error: 'Missing required field: payload' });
        }

        if (!supportedAlgorithms.includes(algorithm)) {
          return res.status(400).json({
            error: 'Unsupported algorithm',
            supported: supportedAlgorithms
          });
        }

        // Check algorithm type and required keys
        const isHMAC = algorithm.startsWith('HS');
        const isRSA = algorithm.startsWith('RS');
        const isECDSA = algorithm.startsWith('ES');

        if (isHMAC && !secret) {
          return res.status(400).json({ error: 'HMAC algorithms require a secret key' });
        }

        if ((isRSA || isECDSA) && !privateKey) {
          return res.status(400).json({ error: `${algorithm} requires a private key` });
        }

        // Create header
        const header = { alg: algorithm, typ: 'JWT' };
        const headerB64 = base64UrlEncode(JSON.stringify(header));

        // Ensure payload has timestamps
        const enrichedPayload = {
          iat: Math.floor(Date.now() / 1000),
          ...payload
        };

        const payloadB64 = base64UrlEncode(JSON.stringify(enrichedPayload));
        const signingInput = `${headerB64}.${payloadB64}`;

        // Sign
        let signature;
        try {
          if (isHMAC) {
            signature = signHMAC(signingInput, secret, algorithm);
          } else if (isRSA) {
            signature = signRSA(signingInput, privateKey, algorithm);
          } else if (isECDSA) {
            signature = signECDSA(signingInput, privateKey, algorithm);
          }
        } catch (err) {
          return res.status(400).json({
            error: 'Signing failed',
            message: err.message,
            hint: isRSA ? 'Ensure private key is in PEM format' : 'Check your secret/key'
          });
        }

        const jwt = `${headerB64}.${payloadB64}.${signature}`;

        return res.status(200).json({
          success: true,
          token: jwt,
          header,
          payload: enrichedPayload,
          signature,
          algorithm
        });
      }

      case 'verify': {
        if (!token) {
          return res.status(400).json({ error: 'Missing required field: token' });
        }

        const parts = token.split('.');
        if (parts.length !== 3) {
          return res.status(400).json({ error: 'Invalid JWT format. Expected 3 parts separated by dots.' });
        }

        const [headerB64, payloadB64, signature] = parts;

        let header, payload;
        try {
          header = JSON.parse(base64UrlDecode(headerB64));
          payload = JSON.parse(base64UrlDecode(payloadB64));
        } catch (err) {
          return res.status(400).json({ error: 'Invalid JWT: malformed base64 or JSON' });
        }

        const tokenAlgo = header.alg;
        if (!supportedAlgorithms.includes(tokenAlgo)) {
          return res.status(400).json({
            error: 'Unsupported algorithm in token',
            algorithm: tokenAlgo
          });
        }

        // Determine verification method
        const isHMAC = tokenAlgo.startsWith('HS');
        const isRSA = tokenAlgo.startsWith('RS');
        const isECDSA = tokenAlgo.startsWith('ES');

        let isValid = false;
        const signingInput = `${headerB64}.${payloadB64}`;

        try {
          if (isHMAC) {
            if (!secret) {
              return res.status(400).json({ error: 'HMAC verification requires secret key' });
            }
            isValid = verifyHMAC(signingInput, signature, secret, tokenAlgo);
          } else if (isRSA) {
            if (!publicKey) {
              return res.status(400).json({ error: 'RSA verification requires public key' });
            }
            isValid = verifyRSA(signingInput, signature, publicKey, tokenAlgo);
          } else if (isECDSA) {
            if (!publicKey) {
              return res.status(400).json({ error: 'ECDSA verification requires public key' });
            }
            isValid = verifyECDSA(signingInput, signature, publicKey, tokenAlgo);
          }
        } catch (err) {
          return res.status(400).json({
            error: 'Verification failed',
            message: err.message
          });
        }

        // Check expiration
        let isExpired = false;
        if (payload.exp) {
          isExpired = Math.floor(Date.now() / 1000) >= payload.exp;
        }

        // Check not before
        let isNotYetValid = false;
        if (payload.nbf) {
          isNotYetValid = Math.floor(Date.now() / 1000) < payload.nbf;
        }

        return res.status(200).json({
          valid: isValid && !isExpired && !isNotYetValid,
          signatureValid: isValid,
          expired: isExpired,
          notYetValid: isNotYetValid,
          header,
          payload,
          algorithm: tokenAlgo
        });
      }

      case 'decode': {
        if (!token) {
          return res.status(400).json({ error: 'Missing required field: token' });
        }

        const parts = token.split('.');
        if (parts.length !== 3) {
          return res.status(400).json({ error: 'Invalid JWT format. Expected 3 parts separated by dots.' });
        }

        const [headerB64, payloadB64] = parts;

        try {
          const header = JSON.parse(base64UrlDecode(headerB64));
          const payload = JSON.parse(base64UrlDecode(payloadB64));

          return res.status(200).json({
            header,
            payload,
            algorithm: header.alg
          });
        } catch (err) {
          return res.status(400).json({ error: 'Invalid JWT: malformed base64 or JSON' });
        }
      }

      case 'generate-keypair': {
        const { type = 'rsa', bits = 2048, namedCurve = 'prime256v1' } = req.body;

        try {
          if (type === 'rsa') {
            const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
              modulusLength: bits,
              publicKeyEncoding: { type: 'spki', format: 'pem' },
              privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
            });

            return res.status(200).json({
              type: 'RSA',
              bits,
              privateKey,
              publicKey
            });
          } else if (type === 'ec') {
            const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
              namedCurve,
              publicKeyEncoding: { type: 'spki', format: 'pem' },
              privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
            });

            return res.status(200).json({
              type: 'EC',
              namedCurve,
              privateKey,
              publicKey
            });
          } else {
            return res.status(400).json({
              error: 'Unsupported key type',
              supported: ['rsa', 'ec']
            });
          }
        } catch (err) {
          return res.status(500).json({
            error: 'Key generation failed',
            message: err.message
          });
        }
      }

      default:
        return res.status(400).json({
          error: 'Unknown action',
          supported: ['generate', 'verify', 'decode', 'generate-keypair']
        });
    }
  } catch (error) {
    console.error('JWT Generator Error:', error);
    return res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
};
