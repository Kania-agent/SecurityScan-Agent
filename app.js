// SecurityScan-Agent — Security Scanner Simulation
const state = {
  scanning: false,
  progress: 0,
  phase: 'Idle',
  findings: [],
  scanLogs: [],
  portResults: []
};

const findings = [
  { title: 'SQL Injection in login endpoint', severity: 'critical', cvss: 9.8, cve: 'CVE-2024-3021', endpoint: '/api/auth/login', desc: 'Unsanitized user input allows arbitrary SQL queries. An attacker can bypass authentication or extract the entire database.', fix: 'Use parameterized queries or ORM. Input validation and WAF rules recommended.' },
  { title: 'Remote Code Execution via file upload', severity: 'critical', cvss: 10.0, cve: 'CVE-2024-5582', endpoint: '/api/upload', desc: 'Server accepts executable file types without validation. Malicious files can be executed on the server.', fix: 'Implement strict file type validation, use a sandboxed upload handler, and scan uploaded files.' },
  { title: 'Cross-Site Scripting (Reflected)', severity: 'high', cvss: 7.5, cve: 'CVE-2024-1893', endpoint: '/search?q=', desc: 'Search parameter is reflected without HTML encoding. Enables phishing and session hijacking attacks.', fix: 'Apply Content-Security-Policy headers and HTML-encode all user output.' },
  { title: 'Privilege Escalation via IDOR', severity: 'high', cvss: 8.1, cve: 'CVE-2024-4100', endpoint: '/api/users/{id}', desc: 'Sequential user IDs expose other users profiles. Authenticated users can access any account.', fix: 'Use UUIDs instead of sequential IDs and enforce authorization checks.' },
  { title: 'Weak TLS Configuration', severity: 'medium', cvss: 5.3, cve: 'CVE-2024-0215', endpoint: 'TLS Config', desc: 'Server supports TLS 1.0/1.1 and weak cipher suites. Susceptible to downgrade attacks.', fix: 'Disable TLS below 1.2, remove weak ciphers, enable HSTS.' },
  { title: 'Server Version Disclosure', severity: 'low', cvss: 2.0, cve: 'N/A', endpoint: 'HTTP Headers', desc: 'Server header reveals nginx version 1.21.3. Aids attackers in finding version-specific exploits.', fix: 'Remove or customize the Server response header.' },
  { title: 'Missing Security Headers', severity: 'medium', cvss: 4.3, cve: 'N/A', endpoint: 'HTTP Response', desc: 'X-Content-Type-Options, X-Frame-Options, and CSP headers are missing from responses.', fix: 'Add X-Content-Type-Options: nosniff, X-Frame-Options: DENY, and a Content-Security-Policy.' },
  { title: 'Open Redirect vulnerability', severity: 'medium', cvss: 6.1, cve: 'CVE-2024-2890', endpoint: '/redirect?url=', desc: 'URL parameter redirects to external domains without validation, enabling phishing attacks.', fix: 'Whitelist allowed redirect targets and validate against a list.' },
  { title: 'JWT Token lacks expiration', severity: 'high', cvss: 7.2, cve: 'N/A', endpoint: '/api/auth/token', desc: 'Issued JWT tokens have no exp claim. Compromised tokens are valid indefinitely.', fix: 'Set short-lived expiration (15min) and implement token refresh flow.' },
  { title: 'Information disclosure in error messages', severity: 'low', cvss: 3.1, cve: 'N/A', endpoint: 'Various', desc: 'Stack traces and database errors are exposed to end users in production mode.', fix: 'Implement custom error pages and log detailed errors server-side only.' },
];

const ports = [
  { port: 22, service: 'SSH', status: 'open' },
  { port: 80, service: 'HTTP', status: 'open' },
  { port: 443, service: 'HTTPS', status: 'open' },
  { port: 3306, service: 'MySQL', status: 'filtered' },
  { port: 5432, service: 'PostgreSQL', status: 'filtered' },
  { port: 6379, service: 'Redis', status: 'open' },
  { port: 8080, service: 'HTTP-Alt', status: 'open' },
  { port: 8443, service: 'HTTPS-Alt', status: 'filtered' },
  { port: 9200, service: 'Elasticsearch', status: 'open' },
  { port: 27017, service: 'MongoDB', status: 'closed' },
];

const scanPhases = [
  { name: 'DNS Resolution', progress: 5 },
  { name: 'TCP Port Scan', progress: 15 },
  { name: 'Service Detection', progress: 25 },
  { name: 'SSL/TLS Analysis', progress: 35 },
  { name: 'Web App Crawling', progress: 50 },
  { name: 'Vulnerability Scanning', progress: 70 },
  { name: 'Exploit Verification', progress: 85 },
  { name: 'Report Generation', progress: 100 },
];

function addScanLog(msg, type = 'info') {
  const log = document.getElementById('scanLog');
  const now = new Date().toTimeString().slice(0, 8);
  const line = document.createElement('div');
  line.className = 'log-line';
  line.innerHTML = `<span class="timestamp">[${now}]</span> <span class="${type}">${msg}</span>`;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

function updateSeverityCounts() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  state.findings.forEach(f => counts[f.severity]++);
  Object.keys(counts).forEach(sev => {
    const el = document.getElementById(`count-${sev}`);
    if (el) el.textContent = counts[sev];
  });
  document.getElementById('totalFindings').textContent = state.findings.length;
}

function addFinding(finding) {
  state.findings.push(finding);
  const container = document.getElementById('findingsList');
  const card = document.createElement('div');
  card.className = `finding-card ${finding.severity}`;
  card.innerHTML = `
    <div class="finding-top">
      <div class="finding-title">${finding.title}</div>
      <span class="finding-severity ${finding.severity}">${finding.severity}</span>
    </div>
    <div class="finding-desc">${finding.desc}</div>
    <div class="finding-meta">
      <span>CVSS: ${finding.cvss}</span>
      <span>${finding.cve}</span>
      <span>${finding.endpoint}</span>
    </div>
  `;
  card.addEventListener('click', () => showDetail(finding));
  container.prepend(card);
  updateSeverityCounts();
}

function showDetail(finding) {
  const overlay = document.getElementById('detailOverlay');
  const box = document.getElementById('detailBox');
  box.innerHTML = `
    <button class="close-btn" onclick="document.getElementById('detailOverlay').classList.remove('visible')">✕</button>
    <h2 style="color: var(--accent-${finding.severity === 'critical' ? 'red' : finding.severity === 'high' ? 'orange' : finding.severity === 'medium' ? 'yellow' : 'blue'})">${finding.title}</h2>
    <div style="margin-bottom: 12px"><span class="finding-severity ${finding.severity}" style="font-size:0.8rem">${finding.severity.toUpperCase()}</span> <span style="margin-left:8px;color:var(--text-secondary)">CVSS: ${finding.cvss} | ${finding.cve}</span></div>
    <p><strong>Endpoint:</strong> <code>${finding.endpoint}</code></p>
    <p>${finding.desc}</p>
    <p><strong>Remediation:</strong><br>${finding.fix}</p>
  `;
  overlay.classList.add('visible');
}

function renderPorts() {
  const container = document.getElementById('portList');
  container.innerHTML = '';
  state.portResults.forEach(p => {
    const div = document.createElement('div');
    div.className = 'port-item';
    div.innerHTML = `
      <span class="port-num">${p.port}</span>
      <span class="port-service">${p.service}</span>
      <span class="port-status-${p.status}">${p.status}</span>
    `;
    container.appendChild(div);
  });
}

function startScan() {
  if (state.scanning) return;
  state.scanning = true;
  state.progress = 0;
  state.findings = [];
  state.portResults = [];
  document.getElementById('findingsList').innerHTML = '';
  document.getElementById('scanLog').innerHTML = '';

  document.body.classList.add('scanning');
  document.getElementById('btnScan').disabled = true;

  addScanLog('Initializing SecurityScan-Agent v2.5...', 'info');
  addScanLog('Target: 192.168.1.0/24, *.example.com', 'info');

  // Simulate scan phases
  let phaseIdx = 0;
  let findingIdx = 0;

  const interval = setInterval(() => {
    state.progress = Math.min(100, state.progress + 0.5);
    document.getElementById('progressBar').style.width = state.progress + '%';
    document.getElementById('progressPct').textContent = Math.floor(state.progress) + '%';

    const currentPhase = scanPhases.find(p => p.progress >= state.progress) || scanPhases[scanPhases.length - 1];
    document.getElementById('scanPhase').textContent = currentPhase.name;

    // Phase transitions
    if (phaseIdx < scanPhases.length && state.progress >= scanPhases[phaseIdx].progress) {
      addScanLog(`Phase complete: ${scanPhases[phaseIdx].name}`, 'ok');
      phaseIdx++;
      if (phaseIdx < scanPhases.length) {
        addScanLog(`Starting: ${scanPhases[phaseIdx].name}...`, 'info');
      }
    }

    // Add port results
    if (state.progress > 15 && state.portResults.length < ports.length && Math.random() < 0.08) {
      state.portResults.push(ports[state.portResults.length]);
      renderPorts();
    }

    // Add findings
    if (state.progress > 50 && findingIdx < findings.length && Math.random() < 0.05) {
      addFinding(findings[findingIdx]);
      addScanLog(`VULN FOUND: ${findings[findingIdx].title} [${findings[findingIdx].severity.toUpperCase()}]`, 'err');
      findingIdx++;
    }

    if (state.progress % 3 < 0.6) {
      addScanLog(`Scanning port range ${1024 + Math.floor(Math.random()*60000)}...`, 'info');
    }

    if (state.progress >= 100) {
      clearInterval(interval);
      state.scanning = false;
      document.body.classList.remove('scanning');
      document.getElementById('btnScan').disabled = false;
      document.getElementById('btnScan').textContent = '▶ Start New Scan';
      addScanLog(`Scan complete. ${state.findings.length} vulnerabilities found.`, 'ok');
    }
  }, 60);
}

// Init
document.getElementById('btnScan').addEventListener('click', startScan);
document.getElementById('detailOverlay').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) e.target.classList.remove('visible');
});

addScanLog('SecurityScan-Agent initialized', 'info');
addScanLog('Waiting for scan target...', 'info');
renderPorts();
