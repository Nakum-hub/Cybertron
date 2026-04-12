const dns = require('node:dns');
const { URL } = require('node:url');

const BLOCKED_IPV4_RANGES = [
  /^127\./, /^10\./, /^172\.(1[6-9]|2[0-9]|3[01])\./, /^192\.168\./,
  /^0\./, /^169\.254\./, /^100\.(6[4-9]|[7-9]\d|1[0-2]\d)\./,
  /^198\.1[89]\./, /^::1$/, /^fc/, /^fd/, /^fe80/,
];

function isBlockedIp(ip) {
  const normalized = String(ip || '').trim();
  if (!normalized) return true;

  // SECURITY FIX: Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
  let checkIp = normalized;
  const v4MappedMatch = normalized.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
  if (v4MappedMatch) {
    checkIp = v4MappedMatch[1];
  }

  return BLOCKED_IPV4_RANGES.some(re => re.test(checkIp));
}

function resolveHostname(hostname) {
  return new Promise((resolve, reject) => {
    dns.resolve4(hostname, (err, addresses) => {
      if (err) {
        dns.resolve6(hostname, (err6, addresses6) => {
          if (err6) {
            reject(new Error(`DNS resolution failed for ${hostname}: ${err.message}`));
            return;
          }
          resolve(addresses6);
        });
        return;
      }
      resolve(addresses);
    });
  });
}

async function validateUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(String(rawUrl));
  } catch {
    return { safe: false, reason: 'invalid_url' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { safe: false, reason: 'invalid_protocol' };
  }

  const hostname = parsed.hostname;

  // Block direct IP addresses in private ranges
  if (isBlockedIp(hostname)) {
    return { safe: false, reason: 'blocked_ip' };
  }

  // Resolve DNS and check resolved IPs (prevents DNS rebinding)
  try {
    const addresses = await resolveHostname(hostname);
    for (const addr of addresses) {
      if (isBlockedIp(addr)) {
        return { safe: false, reason: 'dns_rebinding_blocked', resolvedIp: addr };
      }
    }
  } catch (err) {
    return { safe: false, reason: 'dns_resolution_failed', error: err.message };
  }

  return { safe: true, url: parsed.href };
}

module.exports = { validateUrl, isBlockedIp };
