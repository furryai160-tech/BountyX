// BountyScope Web Dashboard - Client Engine
// Connects to Railway Backend API & Works Seamlessly on Vercel

const DEFAULT_RAILWAY_URL = "https://bkhi-production.up.railway.app";
let backendUrl = localStorage.getItem("bountyscope_backend_url") || "";

// If running on local or same host, default to empty (relative) or localhost:8080
if (!backendUrl) {
  if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") {
    backendUrl = "http://127.0.0.1:8080";
  } else {
    // If on Vercel or remote host, default to the Railway deployment URL
    backendUrl = DEFAULT_RAILWAY_URL;
  }
}

let cachedStats = null;
let cachedFindings = [];
let cachedScope = [];
let cachedPrograms = [];
let cachedQueue = [];
let isPipelinePaused = false;
let autoRefreshTimer = null;

// The 19 Security Tools List
const ARSENAL_TOOLS = [
  { name: "Subfinder", cat: "Recon", role: "Passive Subdomains" },
  { name: "Naabu", cat: "Port Scan", role: "Fast Syn Port Scanning" },
  { name: "HTTPX", cat: "Probing", role: "Web Probing & Tech Fingerprint" },
  { name: "DNSX", cat: "DNS", role: "DNS Bruteforce & Resolution" },
  { name: "Katana", cat: "Crawling", role: "Next-gen Web Spidering" },
  { name: "GAU", cat: "Archive", role: "Wayback & OTX Historical URLs" },
  { name: "Nuclei", cat: "Vuln Scan", role: "Surgical CVE & 0-Day Templates" },
  { name: "Dalfox", cat: "XSS Hunter", role: "Parameter Injection & DOM XSS" },
  { name: "SQLMap", cat: "SQLi", role: "Automated SQL Injection Detector" },
  { name: "Arjun", cat: "Params", role: "Hidden HTTP Parameter Discovery" },
  { name: "FFUF", cat: "Fuzzing", role: "High-speed Directory & API Fuzzing" },
  { name: "CRLFuzz", cat: "Injection", role: "CRLF Header Injection Scanner" },
  { name: "KXSS", cat: "XSS", role: "Reflected Character Reflection Probe" },
  { name: "Gitleaks", cat: "Secrets", role: "Secret & API Key Token Scanner" },
  { name: "GoSpider", cat: "Spider", role: "Deep Web Crawler & JS Scraping" },
  { name: "Smuggler", cat: "Smuggling", role: "HTTP Request Smuggling Scanner" },
  { name: "ParamSpider", cat: "Mining", role: "URL Parameter Extraction" },
  { name: "AlterX", cat: "Mutations", role: "Subdomain Wordlist Permutations" },
  { name: "Amass", cat: "OSINT", role: "Network Mapping & ASN Recon" },
  { name: "Takeover Radar", cat: "Rust Engine", role: "DNS Dangling CNAME Scanner" },
  { name: "JS Miner", cat: "Rust Engine", role: "Secrets & API Endpoint Extractor" },
  { name: "CORS Scanner", cat: "Rust Engine", role: "Misconfigured Access-Control Probe" },
  { name: "Bypass 403", cat: "Rust Engine", role: "Forbidden Headers Bypass Engine" },
];

document.addEventListener("DOMContentLoaded", () => {
  initLiveClock();
  initNavigation();
  initToolsGrid();
  updateBackendDisplay();
  
  // Initial fetch
  loadAllData();

  // Auto-refresh every 6 seconds
  autoRefreshTimer = setInterval(loadAllData, 6000);
});

function initLiveClock() {
  const clockEl = document.getElementById("liveClock");
  function update() {
    const now = new Date();
    clockEl.textContent = now.toLocaleTimeString("ar-EG", { hour12: false });
  }
  update();
  setInterval(update, 1000);
}

function initNavigation() {
  const navButtons = document.querySelectorAll(".nav-item");
  navButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      switchTab(targetTab);
    });
  });
}

function switchTab(tabId) {
  // Update nav buttons
  document.querySelectorAll(".nav-item").forEach(btn => {
    if (btn.getAttribute("data-tab") === tabId) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  // Update tab panes
  document.querySelectorAll(".tab-pane").forEach(pane => {
    pane.classList.remove("active");
  });

  const activePane = document.getElementById(`tab-${tabId}`);
  if (activePane) {
    activePane.classList.add("active");
  }

  // Update header titles
  const titles = {
    overview: { title: "مركز العمليات الأمنية (Command Center)", sub: "متابعة الفحص الحي لـ 19 أداة أمنية متزامنة مع HackerOne" },
    findings: { title: "مركز الثغرات الأمنية (Findings Hub)", sub: "استعراض الثغرات المكتشفة وأدلة الإثبات Proof of Concept" },
    scope: { title: "رادار النطاقات والأصول (Scope Radar)", sub: "جميع الدومينات المصرح بها في برامج HackerOne" },
    programs: { title: "برامج HackerOne المتتبعة", sub: "قائمة برامج المكافآت التابعة لحسابك المربوط" },
    queue: { title: "طابور الفحص والعمال (Recon Queue)", sub: "المهام الجارية والمنتظرة في خط الأتمتة" },
    reports: { title: "تقارير الثغرات (Markdown Reports)", sub: "مسودات التقارير الجاهزة للتقديم على منصات المكافآت" },
    health: { title: "فحص صحة الأدوات والموارد", sub: "التحقق من جاهزية الـ 19 أداة أمنية وموارد السيرفر" },
  };

  if (titles[tabId]) {
    document.getElementById("pageTitle").textContent = titles[tabId].title;
    document.getElementById("pageSubtitle").textContent = titles[tabId].sub;
  }

  // Refresh tab specific data
  if (tabId === "findings") renderFindingsTable(cachedFindings);
  if (tabId === "scope") renderScopeTable(cachedScope);
  if (tabId === "programs") renderProgramsTable(cachedPrograms);
  if (tabId === "queue") loadQueue();
  if (tabId === "reports") loadReports();
  if (tabId === "health") loadHealth();
}

function initToolsGrid() {
  const grid = document.getElementById("toolsMiniGrid");
  if (!grid) return;
  grid.innerHTML = ARSENAL_TOOLS.map(t => `
    <div class="tool-badge-item active" title="${t.role}">
      <span>${t.name}</span>
      <span class="dot"></span>
    </div>
  `).join("");
}

function updateBackendDisplay() {
  const el = document.getElementById("displayBackendUrl");
  const pill = document.getElementById("connStatusPill");
  const text = document.getElementById("connStatusText");

  if (el) el.textContent = backendUrl || "Localhost (Port 8080)";
}

// API Fetch Helper
async function apiFetch(endpoint, options = {}) {
  const url = `${backendUrl.replace(/\/$/, "")}${endpoint}`;
  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
        ...(options.headers || {})
      }
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    return await res.json();
  } catch (err) {
    console.warn(`Fetch error for ${endpoint}:`, err);
    return null;
  }
}

// Main Load Data Routine
async function loadAllData() {
  const [statsData, findingsData, scopeData, programsData, queueData] = await Promise.all([
    apiFetch("/api/stats"),
    apiFetch("/api/findings"),
    apiFetch("/api/scope"),
    apiFetch("/api/programs"),
    apiFetch("/api/queue")
  ]);

  const pill = document.getElementById("connStatusPill");
  const text = document.getElementById("connStatusText");
  const dot = pill.querySelector(".status-dot");

  if (statsData && statsData.ok) {
    dot.className = "status-dot online";
    text.textContent = "متصل بالسيرفر 🟢";
    renderStats(statsData);
  } else {
    dot.className = "status-dot offline";
    text.textContent = "جاري الاتصال بالسيرفر 🟡";
  }

  if (findingsData && findingsData.ok) {
    cachedFindings = findingsData.findings || [];
    document.getElementById("findingsNavCount").textContent = cachedFindings.length;
    renderFindingsOverview(cachedFindings);
    if (document.getElementById("tab-findings").classList.contains("active")) {
      renderFindingsTable(cachedFindings);
    }
  }

  if (scopeData && scopeData.ok) {
    cachedScope = scopeData.assets || [];
    document.getElementById("scopeNavCount").textContent = cachedScope.length;
    if (document.getElementById("tab-scope").classList.contains("active")) {
      renderScopeTable(cachedScope);
    }
  }

  if (programsData && programsData.ok) {
    cachedPrograms = programsData.programs || [];
    document.getElementById("programsNavCount").textContent = cachedPrograms.length;
    if (document.getElementById("tab-programs").classList.contains("active")) {
      renderProgramsTable(cachedPrograms);
    }
  }

  if (queueData && queueData.ok) {
    cachedQueue = queueData.jobs || [];
    const pendingOrRunning = cachedQueue.filter(j => j.status === 'pending' || j.status === 'running').length;
    document.getElementById("queueNavCount").textContent = pendingOrRunning;
    renderQueueOverview(cachedQueue);
    if (document.getElementById("tab-queue").classList.contains("active")) {
      renderFullQueueTable(cachedQueue);
    }
  }
}

function renderStats(data) {
  cachedStats = data;
  isPipelinePaused = data.is_paused || false;

  const pauseBtnIcon = document.getElementById("pauseBtnIcon");
  const pauseBtnText = document.getElementById("pauseBtnText");
  const workerStatus = document.getElementById("statWorkerStatus");

  if (isPipelinePaused) {
    pauseBtnIcon.textContent = "▶️";
    pauseBtnText.textContent = "استئناف الفحص";
    workerStatus.textContent = "حالة الخط: متوقف مؤقتاً ⏸️";
  } else {
    pauseBtnIcon.textContent = "⏸️";
    pauseBtnText.textContent = "إيقاف مؤقت";
    workerStatus.textContent = "حالة الخط: يعمل بنشاط 🟢";
  }

  const s = data.stats || {};
  document.getElementById("statCriticalFindings").textContent = s.critical_findings || 0;
  document.getElementById("statHighFindings").textContent = s.high_findings || 0;
  document.getElementById("statMediumFindings").textContent = s.medium_findings || 0;
  document.getElementById("statInScopeAssets").textContent = s.in_scope_assets || 0;
  document.getElementById("statSubdomainsText").textContent = `${s.discovered_subdomains || 0} نطاق فرعي نشط`;
  document.getElementById("statTotalPrograms").textContent = s.total_programs || 0;
  document.getElementById("statActiveWorkers").textContent = data.max_workers || 10;
}

function renderFindingsOverview(findings) {
  const tbody = document.getElementById("overviewFindingsBody");
  if (!tbody) return;

  if (findings.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="loading-cell">لا توجد ثغرات مكتشفة حتى الآن. المحرك يفحص في الخلفية...</td></tr>`;
    return;
  }

  tbody.innerHTML = findings.slice(0, 5).map(f => {
    const sevBadge = getSeverityBadge(f.severity);
    return `
      <tr>
        <td>${sevBadge}</td>
        <td><b>${escapeHtml(f.template_name || f.template_id)}</b></td>
        <td><code class="font-mono">${escapeHtml(f.asset)}</code></td>
        <td>${formatDate(f.created_at)}</td>
        <td>
          <button class="btn-primary-sm" onclick="viewFindingEvidence('${f.id}')">عرض الدليل</button>
        </td>
      </tr>
    `;
  }).join("");
}

function renderFindingsTable(findings) {
  const tbody = document.getElementById("allFindingsTableBody");
  if (!tbody) return;

  if (findings.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="loading-cell">لا توجد ثغرات مسجلة حتى الآن</td></tr>`;
    return;
  }

  tbody.innerHTML = findings.map(f => {
    const sevBadge = getSeverityBadge(f.severity);
    return `
      <tr>
        <td>${sevBadge}</td>
        <td><b>${escapeHtml(f.template_name || f.template_id)}</b></td>
        <td><code>${escapeHtml(f.program_handle)}</code></td>
        <td><code class="font-mono">${escapeHtml(f.asset)}</code></td>
        <td><a href="${escapeHtml(f.url)}" target="_blank" class="link-btn font-mono">${escapeHtml(f.url)}</a></td>
        <td>${formatDate(f.created_at)}</td>
        <td>
          <button class="btn-primary-sm" onclick="viewFindingEvidence('${f.id}')">🔍 الدليل والتقرير</button>
        </td>
      </tr>
    `;
  }).join("");
}

function renderScopeTable(assets) {
  const tbody = document.getElementById("scopeTableBody");
  if (!tbody) return;

  if (assets.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="loading-cell">جاري مزامنة النطاقات مع HackerOne...</td></tr>`;
    return;
  }

  tbody.innerHTML = assets.slice(0, 50).map(a => `
    <tr>
      <td><b class="font-mono text-cyan">${escapeHtml(a.identifier)}</b></td>
      <td><code>${escapeHtml(a.program_id)}</code></td>
      <td><span class="badge badge-low">${escapeHtml(a.asset_type)}</span></td>
      <td>${a.bounty_eligible ? "💰 نعم" : "📋 VDP"}</td>
      <td><span class="badge-status status-completed">In-Scope ✅</span></td>
      <td>
        <button class="btn-primary-sm" onclick="quickScanTarget('${a.identifier}', '${a.program_id}')">🚀 فحص الآن</button>
      </td>
    </tr>
  `).join("");
}

function renderProgramsTable(programs) {
  const tbody = document.getElementById("programsTableBody");
  if (!tbody) return;

  if (programs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="loading-cell">جاري تحميل برامج HackerOne...</td></tr>`;
    return;
  }

  tbody.innerHTML = programs.map(p => `
    <tr>
      <td><b>${escapeHtml(p.name)}</b></td>
      <td><code>${escapeHtml(p.handle)}</code></td>
      <td>${p.offers_bounties ? "<span class='badge badge-medium'>💰 مكافآت</span>" : "<span class='badge badge-low'>📋 VDP</span>"}</td>
      <td><span class="badge-status status-completed">${escapeHtml(p.submission_state)}</span></td>
      <td><a href="${escapeHtml(p.url || '#')}" target="_blank" class="link-btn">رابط HackerOne</a></td>
      <td>
        <button class="btn-secondary-sm" onclick="quickScanTarget('${p.handle}', '${p.handle}')">⚡ فحص البرنامج</button>
      </td>
    </tr>
  `).join("");
}

function renderQueueOverview(queue) {
  const tbody = document.getElementById("overviewQueueBody");
  if (!tbody) return;

  if (queue.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="loading-cell">الطابور فارغ حالياً. المحرك جاهز لمهام جديدة.</td></tr>`;
    return;
  }

  tbody.innerHTML = queue.slice(0, 5).map(j => {
    const statusBadge = getStatusBadge(j.status);
    return `
      <tr>
        <td><b class="font-mono">${escapeHtml(j.target)}</b></td>
        <td><code>${escapeHtml(j.program_handle)}</code></td>
        <td>${statusBadge}</td>
        <td>${j.attempts} / 3</td>
        <td>${formatDate(j.created_at)}</td>
      </tr>
    `;
  }).join("");
}

function renderFullQueueTable(queue) {
  const tbody = document.getElementById("fullQueueTableBody");
  if (!tbody) return;

  tbody.innerHTML = queue.map(j => {
    const statusBadge = getStatusBadge(j.status);
    return `
      <tr>
        <td><code class="font-mono">${j.id.slice(0, 8)}...</code></td>
        <td><b class="font-mono text-cyan">${escapeHtml(j.target)}</b></td>
        <td><code>${escapeHtml(j.program_handle)}</code></td>
        <td>${statusBadge}</td>
        <td>${j.attempts} / 3</td>
        <td><span class="text-danger">${escapeHtml(j.error_message || "-")}</span></td>
        <td>${formatDate(j.created_at)}</td>
      </tr>
    `;
  }).join("");
}

async function loadReports() {
  const data = await apiFetch("/api/reports");
  const tbody = document.getElementById("reportsTableBody");
  if (!tbody) return;

  if (!data || !data.ok || data.reports.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="loading-cell">لا توجد تقارير منشأة حتى الآن</td></tr>`;
    return;
  }

  tbody.innerHTML = data.reports.map(r => `
    <tr>
      <td><b>${escapeHtml(r.title)}</b></td>
      <td><code class="font-mono">${escapeHtml(r.file_path)}</code></td>
      <td>${r.human_verified ? "✅ موثق" : "⏳ يتطلب مراجعة"}</td>
      <td>${formatDate(r.created_at)}</td>
      <td>
        <button class="btn-primary-sm" onclick="showReportModal('${escapeHtml(r.title)}', \`${escapeHtml(r.markdown_content).replace(/`/g, "\\`")}\`)">📄 معاينة التقرير</button>
      </td>
    </tr>
  `).join("");
}

async function loadHealth() {
  const data = await apiFetch("/api/health");
  const tbody = document.getElementById("healthTableBody");
  if (!tbody) return;

  if (!data || !data.ok) {
    tbody.innerHTML = `<tr><td colspan="5" class="loading-cell">تعذر الاتصال بخدمة فحص الصحة</td></tr>`;
    return;
  }

  tbody.innerHTML = data.checks.map(c => `
    <tr>
      <td><span class="badge badge-low">${escapeHtml(c.category)}</span></td>
      <td><b>${escapeHtml(c.name)}</b></td>
      <td>${c.status ? "<span class='badge-status status-completed'>[OK] يعمل بنجاح</span>" : "<span class='badge-status status-failed'>[FAILED] متوقف</span>"}</td>
      <td><code class="font-mono">${escapeHtml(c.path || "-")}</code></td>
      <td>${escapeHtml(c.details)}</td>
    </tr>
  `).join("");
}

async function viewFindingEvidence(findingId) {
  const data = await apiFetch(`/api/findings/${findingId}/evidence`);
  const modal = document.getElementById("evidenceModal");
  const body = document.getElementById("evidenceModalBody");
  const title = document.getElementById("evidenceModalTitle");

  title.textContent = `دليل إثبات الثغرة (POC) - معرف: ${findingId.slice(0, 8)}`;

  if (data && data.ok && data.evidence) {
    const e = data.evidence;
    body.innerHTML = `
      <div class="evidence-section">
        <h4 style="margin-bottom: 8px; color: var(--primary)">أمر cURL لإعادة توليد الثغرة:</h4>
        <pre class="code-block"><code>${escapeHtml(e.curl_command || "N/A")}</code></pre>

        <h4 style="margin-bottom: 8px; color: var(--high)">طلب HTTP المُرسل (HTTP Request):</h4>
        <pre class="code-block"><code>${escapeHtml(e.request_raw || "N/A")}</code></pre>

        <h4 style="margin-bottom: 8px; color: var(--success)">استجابة السيرفر (HTTP Response):</h4>
        <pre class="code-block"><code>${escapeHtml(e.response_raw || "N/A")}</code></pre>
      </div>
    `;
  } else {
    body.innerHTML = `<p class="loading-cell">لا يوجد دليل تفصيلي إضافي مسجل لهذه الثغرة.</p>`;
  }

  modal.classList.add("open");
}

function showReportModal(title, content) {
  const modal = document.getElementById("evidenceModal");
  const body = document.getElementById("evidenceModalBody");
  const titleEl = document.getElementById("evidenceModalTitle");

  titleEl.textContent = title;
  body.innerHTML = `
    <div style="display: flex; justify-content: flex-end; margin-bottom: 12px;">
      <button class="btn-primary-sm" onclick="copyReportContent()">📋 نسخ التقرير لـ HackerOne</button>
    </div>
    <pre class="code-block" id="reportContentText" style="max-height: 50vh;"><code>${escapeHtml(content)}</code></pre>
  `;

  modal.classList.add("open");
}

function copyReportContent() {
  const text = document.getElementById("reportContentText").innerText;
  navigator.clipboard.writeText(text);
  alert("✅ تم نسخ التقرير بنجاح!");
}

function closeEvidenceModal() {
  document.getElementById("evidenceModal").classList.remove("open");
}

function openQuickScanModal() {
  document.getElementById("scanModal").classList.add("open");
}

function closeScanModal() {
  document.getElementById("scanModal").classList.remove("open");
}

async function quickScanTarget(target, program) {
  if (!confirm(`هل تريد بدء فحص شامل لـ '${target}' بالـ 19 أداة فوراً؟`)) return;
  const res = await apiFetch("/api/scan", {
    method: "POST",
    body: JSON.stringify({ target, program: program || "manual" })
  });

  if (res && res.ok) {
    alert(`🚀 تم إدراج '${target}' في طابور الفحص بنجاح! رقم المهمة: ${res.job_id}`);
    loadAllData();
  } else {
    alert("❌ فشل إدراج الهدف: " + (res ? res.error : "خطأ اتصال"));
  }
}

async function submitQuickScan() {
  const target = document.getElementById("scanTargetInput").value.trim();
  const program = document.getElementById("scanProgramInput").value.trim() || "manual";

  if (!target) {
    alert("يرجى إدخال اسم الهدف");
    return;
  }

  const res = await apiFetch("/api/scan", {
    method: "POST",
    body: JSON.stringify({ target, program })
  });

  if (res && res.ok) {
    alert(`🚀 تم إدراج '${target}' في طابور الفحص بنجاح! رقم المهمة: ${res.job_id}`);
    closeScanModal();
    document.getElementById("scanTargetInput").value = "";
    loadAllData();
  } else {
    alert("❌ فشل إدراج الهدف: " + (res ? res.error : "خطأ اتصال"));
  }
}

async function togglePausePipeline() {
  const endpoint = isPipelinePaused ? "/api/control/resume" : "/api/control/pause";
  const res = await apiFetch(endpoint, { method: "POST" });
  if (res && res.ok) {
    isPipelinePaused = res.is_paused;
    loadAllData();
  }
}

function manualRefreshData() {
  const btn = document.getElementById("refreshBtn");
  btn.style.opacity = "0.5";
  loadAllData().finally(() => {
    btn.style.opacity = "1";
  });
}

function openSettingsModal() {
  document.getElementById("settingsBackendUrl").value = backendUrl;
  document.getElementById("testConnResult").style.display = "none";
  document.getElementById("settingsModal").classList.add("open");
}

function closeSettingsModal() {
  document.getElementById("settingsModal").classList.remove("open");
}

async function testBackendConnection() {
  const inputUrl = document.getElementById("settingsBackendUrl").value.trim();
  const resDiv = document.getElementById("testConnResult");
  resDiv.className = "test-conn-result";
  resDiv.style.display = "block";
  resDiv.textContent = "جاري اختبار الاتصال...";

  try {
    const res = await fetch(`${inputUrl.replace(/\/$/, "")}/api/stats`);
    if (res.ok) {
      const data = await res.json();
      resDiv.className = "test-conn-result success";
      resDiv.textContent = `✅ الاتصال ناجح! تم التعرف على السيرفر (برامج: ${data.stats.total_programs}, أصول: ${data.stats.in_scope_assets})`;
    } else {
      resDiv.className = "test-conn-result error";
      resDiv.textContent = `⚠️ استجاب السيرفر برمز خطأ: ${res.status}`;
    }
  } catch (e) {
    resDiv.className = "test-conn-result error";
    resDiv.textContent = `❌ فشل الاتصال: تأكد من رابط السيرفر (${e.message})`;
  }
}

function saveSettings() {
  const inputUrl = document.getElementById("settingsBackendUrl").value.trim();
  backendUrl = inputUrl;
  localStorage.setItem("bountyscope_backend_url", backendUrl);
  updateBackendDisplay();
  closeSettingsModal();
  loadAllData();
}

// Helpers
function getSeverityBadge(sev) {
  const s = (sev || "").toLowerCase();
  if (s === "critical") return `<span class="badge badge-critical">🚨 حرج</span>`;
  if (s === "high") return `<span class="badge badge-high">🟠 عالي</span>`;
  if (s === "medium") return `<span class="badge badge-medium">🟡 متوسط</span>`;
  return `<span class="badge badge-low">ℹ️ منخفض</span>`;
}

function getStatusBadge(status) {
  const s = (status || "").toLowerCase();
  if (s === "completed") return `<span class="badge-status status-completed">مكتمل ✅</span>`;
  if (s === "running") return `<span class="badge-status status-running">قيد الفحص ⚡</span>`;
  if (s === "pending") return `<span class="badge-status status-pending">في الانتظار ⏳</span>`;
  return `<span class="badge-status status-failed">فشل ❌</span>`;
}

function formatDate(isoStr) {
  if (!isoStr) return "-";
  try {
    const d = new Date(isoStr);
    return d.toLocaleString("ar-EG", { dateStyle: "short", timeStyle: "short" });
  } catch {
    return isoStr;
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
