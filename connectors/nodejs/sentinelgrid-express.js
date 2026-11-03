/**
 * SentinelGrid In-Line WAAP Middleware for Express / NestJS
 * Features: Keep-Alive HTTP agent, fail-open policy, exact header propagation.
 * Author: Anup Dhokiya (@anup-dhokiya) - Lead Architect
 */

const http = require('http');

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

class SentinelGridExpress {
  constructor(options = {}) {
    this.sentinelgridUrl = options.sentinelgridUrl || 'http://127.0.0.1:8000/v1/inspect';
    this.websiteId = options.websiteId || 'default-site';
    this.timeoutMs = options.timeoutMs || 50;
    this.failOpen = options.failOpen !== false;

    const parsed = new URL(this.sentinelgridUrl);
    this.agent = new http.Agent({
      keepAlive: true,
      maxSockets: 100,
      maxFreeSockets: 20
    });
    this.requestOptions = {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || 8000,
      path: parsed.pathname,
      method: 'POST',
      agent: this.agent,
      headers: { 'Content-Type': 'application/json' },
      timeout: this.timeoutMs
    };
  }

  middleware() {
    return (req, res, next) => {
      // 1. Resolve client IP
      const clientIp = (
        req.headers['x-real-ip'] ||
        (req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : null) ||
        (req.socket ? req.socket.remoteAddress : '127.0.0.1') ||
        '127.0.0.1'
      );

      // 2. Format request body
      let bodyStr = '';
      if (req.body) {
        bodyStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
      }

      // 3. Assemble SentinelGrid payload
      const payload = JSON.stringify({
        website_id: this.websiteId,
        method: req.method,
        path: req.path,
        query_params: new URLSearchParams(req.query).toString(),
        body: bodyStr.slice(0, 65536),
        headers: req.headers,
        client_ip: clientIp
      });

      let finished = false;
      const inspectReq = http.request(this.requestOptions, (inspectRes) => {
        let rawData = '';
        inspectRes.on('data', (chunk) => { rawData += chunk; });
        inspectRes.on('end', () => {
          if (finished) return;
          finished = true;

          try {
            if (inspectRes.statusCode === 200) {
              const decision = JSON.parse(rawData);
              if (decision.action === 'BLOCK') {
                const eventId = decision.event_id || 'N/A';
                const rule = decision.rule_triggered || 'BLOCKED';
                res.status(403)
                   .set('X-SentinelGrid-Action', 'BLOCK')
                   .set('X-SentinelGrid-Event-ID', eventId)
                   .set('X-SentinelGrid-Rule', rule)
                   .send(`<h3>403 Forbidden: Blocked by SentinelGrid WAAP [${escapeHtml(eventId)}]</h3>`);
                return;
              }
            }
          } catch (e) {
            // Parse error: fall through to next()
          }
          next();
        });
      });

      inspectReq.on('timeout', () => {
        inspectReq.destroy();
        if (!finished) {
          finished = true;
          if (this.failOpen) next();
          else res.status(503).send('503 Service Unavailable: Security Timeout');
        }
      });

      inspectReq.on('error', (err) => {
        if (!finished) {
          finished = true;
          if (this.failOpen) next();
          else res.status(503).send('503 Service Unavailable: Security Agent Error');
        }
      });

      inspectReq.write(payload);
      inspectReq.end();
    };
  }
}

module.exports = SentinelGridExpress;
