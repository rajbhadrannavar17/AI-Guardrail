import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  AlertOctagon,
  BarChart3,
  Bell,
  CheckCircle2,
  ChevronRight,
  Database,
  FileLock2,
  FileText,
  Gauge,
  KeyRound,
  LayoutDashboard,
  LockKeyhole,
  MessageSquareText,
  Network,
  RadioTower,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Upload,
  UserCog,
  Users,
} from "lucide-react";
import "./styles.css";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

const navItems = [
  ["Dashboard", LayoutDashboard],
  ["AI Chat", MessageSquareText],
  ["Policies", FileLock2],
  ["Prompt Logs", Database],
  ["Approvals", CheckCircle2],
  ["Analytics", BarChart3],
  ["Threat Intel", RadioTower],
  ["Users", Users],
  ["Settings", SlidersHorizontal],
  ["Admin", UserCog],
];

const riskTone = {
  Low: "low",
  Medium: "medium",
  High: "high",
  Critical: "critical",
};

const defaultPrompt =
  "Can you rewrite this support message for a customer? Contact them at alex@example.com and remove any sensitive details before sending.";

function Panel({ title, icon: Icon, action, children, className = "" }) {
  return (
    <section className={`panel ${className}`}>
      <div className="panelHeader">
        <div className="panelTitle">
          <Icon size={18} />
          <h2>{title}</h2>
        </div>
        {action}
      </div>
      <div className="panelBody">{children}</div>
    </section>
  );
}

function Stat({ label, value, tone = "neutral" }) {
  return (
    <div className={`stat stat-${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Badge({ children, tone = "neutral" }) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

function App() {
  const [active, setActive] = useState("Dashboard");
  const [dark, setDark] = useState(true);
  const [prompt, setPrompt] = useState(defaultPrompt);
  const [profile, setProfile] = useState({
    user_email: "employee@company.local",
    department: "Engineering",
    role: "Employee",
    device: "Managed MacBook",
    browser: "Chrome",
  });
  const [chatResult, setChatResult] = useState(null);
  const [logs, setLogs] = useState([]);
  const [analytics, setAnalytics] = useState({});
  const [policies, setPolicies] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [docs, setDocs] = useState({ architecture: [], controls: [], compliance: [] });
  const [loading, setLoading] = useState(false);

  const latest = logs[0];
  const stats = useMemo(
    () => [
      ["Blocked Prompts", analytics.blocked || 0, "critical"],
      ["Redacted Prompts", analytics.redacted || 0, "medium"],
      ["Allowed Prompts", analytics.allowed || 0, "low"],
      ["Approval Queue", analytics.approvals || 0, "high"],
    ],
    [analytics],
  );

  async function loadAll() {
    const [logsRes, analyticsRes, policiesRes, approvalsRes, docsRes] = await Promise.all([
      fetch(`${API}/api/guardrail/logs`),
      fetch(`${API}/api/guardrail/analytics`),
      fetch(`${API}/api/guardrail/policies`),
      fetch(`${API}/api/guardrail/approvals`),
      fetch(`${API}/api/guardrail/documentation`),
    ]);
    setLogs(await logsRes.json());
    setAnalytics(await analyticsRes.json());
    setPolicies(await policiesRes.json());
    setApprovals(await approvalsRes.json());
    setDocs(await docsRes.json());
  }

  useEffect(() => {
    loadAll().catch(() => {});
  }, []);

  async function sendPrompt() {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/guardrail/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...profile, prompt }),
      });
      const data = await res.json();
      setChatResult(data);
      await loadAll();
    } finally {
      setLoading(false);
    }
  }

  async function requestApproval(logId) {
    await fetch(`${API}/api/guardrail/approvals`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        log_id: logId,
        requested_by: profile.user_email,
        approver_role: "Manager",
        reason: "Business justification submitted from the AI Guardrail portal.",
      }),
    });
    await loadAll();
  }

  function setProfileField(key, value) {
    setProfile((current) => ({ ...current, [key]: value }));
  }

  return (
    <main className={dark ? "appShell dark" : "appShell light"}>
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck size={24} />
          <div>
            <strong>AI Guardrail</strong>
            <span>Enterprise DLP Gateway</span>
          </div>
        </div>
        <nav>
          {navItems.map(([item, Icon]) => (
            <button key={item} className={active === item ? "active" : ""} onClick={() => setActive(item)}>
              <Icon size={17} />
              {item}
            </button>
          ))}
        </nav>
        <button className="themeToggle" onClick={() => setDark((value) => !value)}>
          {dark ? "Light Mode" : "Dark Mode"}
        </button>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>{active}</h1>
            <p>Secure gateway for employee prompts, model routing, response inspection, approvals, and audit evidence.</p>
          </div>
          <div className="topActions">
            <a className="ghostBtn" href={`${API}/docs`} target="_blank" rel="noreferrer">
              API Docs
            </a>
            <a className="ghostBtn" href={`${API}/api/guardrail/logs/export.csv`} target="_blank" rel="noreferrer">
              Export CSV
            </a>
          </div>
        </header>

        <section className="statsGrid">
          {stats.map(([label, value, tone]) => (
            <Stat key={label} label={label} value={value} tone={tone} />
          ))}
        </section>

        <section className="mainGrid">
          <Panel title="AI Chat Gateway" icon={MessageSquareText} className="span2">
            <div className="chatShell">
              <div className="profileGrid">
                <input value={profile.user_email} onChange={(event) => setProfileField("user_email", event.target.value)} />
                <select value={profile.department} onChange={(event) => setProfileField("department", event.target.value)}>
                  {["Engineering", "Finance", "HR", "Support", "Security", "Legal", "Executive"].map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
                <select value={profile.role} onChange={(event) => setProfileField("role", event.target.value)}>
                  {["Employee", "Manager", "Security Analyst", "SOC Analyst", "Compliance Officer", "Administrator", "CISO"].map((item) => (
                    <option key={item}>{item}</option>
                  ))}
                </select>
              </div>
              <div className="dropZone">
                <Upload size={18} />
                <span>File, PDF, image, and voice inputs are represented in this demo by pasted text inspection.</span>
              </div>
              <textarea value={prompt} onChange={(event) => setPrompt(event.target.value)} />
              <button className="primaryBtn" onClick={sendPrompt} disabled={loading}>
                <ShieldCheck size={17} />
                {loading ? "Inspecting..." : "Send Through Guardrail"}
              </button>
            </div>
          </Panel>

          <Panel title="Prompt Risk" icon={Gauge}>
            {!chatResult && <p className="empty">Submit a prompt to see policy action, redaction preview, routing, and approval status.</p>}
            {chatResult && (
              <div className="riskCard">
                <Badge tone={riskTone[chatResult.guardrail.risk_level]}>{chatResult.guardrail.risk_level}</Badge>
                <strong>{chatResult.guardrail.action.replaceAll("_", " ")}</strong>
                <span>Score {chatResult.guardrail.risk_score}/100</span>
                <p>{chatResult.guardrail.decision_reason}</p>
                <small>Route: {chatResult.guardrail.model_route}</small>
                {chatResult.guardrail.approval_required && (
                  <button className="secondaryBtn" onClick={() => requestApproval(chatResult.log_id)}>
                    Request Approval
                  </button>
                )}
              </div>
            )}
          </Panel>

          <Panel title="Redaction Preview" icon={FileText} className="span2">
            <pre className="previewBox">{chatResult?.guardrail?.redacted_prompt || "Sensitive values will be replaced with typed redaction markers before routing."}</pre>
          </Panel>

          <Panel title="Model Response" icon={Network}>
            <div className="responseBox">
              {chatResult?.delivered ? chatResult.message : "No response delivered until policy allows the prompt and response inspection passes."}
            </div>
          </Panel>

          <Panel title="Detection Findings" icon={ShieldAlert} className="span3">
            <div className="findingGrid">
              {(chatResult?.guardrail?.findings || latest?.findings || []).map((finding, index) => (
                <article key={`${finding.rule}-${index}`} className="findingCard">
                  <div>
                    <Badge tone={riskTone[finding.risk]}>{finding.risk}</Badge>
                    <h3>{finding.rule}</h3>
                  </div>
                  <p>{finding.category}</p>
                  <small>{finding.preview}</small>
                </article>
              ))}
              {!(chatResult?.guardrail?.findings || latest?.findings || []).length && <p className="empty">No detections in the current prompt.</p>}
            </div>
          </Panel>

          <Panel title="Policy Engine" icon={LockKeyhole} className="span2">
            <div className="policyList">
              {policies.map((policy) => (
                <article key={policy.id}>
                  <div>
                    <Badge>{policy.id}</Badge>
                    <strong>{policy.name}</strong>
                  </div>
                  <p>{policy.condition}</p>
                  <span>{policy.action} | {policy.routing}</span>
                </article>
              ))}
            </div>
          </Panel>

          <Panel title="Executive Dashboard" icon={BarChart3}>
            <div className="barList">
              {Object.entries(analytics.risks || {}).map(([risk, count]) => (
                <div key={risk}>
                  <span>{risk}</span>
                  <meter min="0" max={Math.max(5, analytics.total || 1)} value={count} />
                  <strong>{count}</strong>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Approvals" icon={CheckCircle2}>
            <div className="approvalList">
              {approvals.map((item) => (
                <article key={item.id}>
                  <strong>Log #{item.log_id}</strong>
                  <span>{item.status}</span>
                  <small>{item.approver_role}</small>
                </article>
              ))}
              {!approvals.length && <p className="empty">No active approval records.</p>}
            </div>
          </Panel>

          <Panel title="Threat Intelligence" icon={RadioTower}>
            <div className="intelList">
              {["Known leaked credential formats", "Prompt jailbreak phrases", "Internal URL exposure", "Mass upload behavior", "Malicious domain indicators"].map((item) => (
                <div key={item}>
                  <AlertOctagon size={16} />
                  <span>{item}</span>
                </div>
              ))}
            </div>
          </Panel>

          <Panel title="Audit Logs" icon={Database} className="span3">
            <div className="logTable">
              <div className="logHead">
                <span>User</span>
                <span>Department</span>
                <span>Risk</span>
                <span>Action</span>
                <span>Model</span>
                <span>Time</span>
              </div>
              {logs.map((log) => (
                <button key={log.id} onClick={() => setChatResult({ log_id: log.id, delivered: false, guardrail: log })}>
                  <span>{log.user_email}</span>
                  <span>{log.department}</span>
                  <Badge tone={riskTone[log.risk_level]}>{log.risk_level}</Badge>
                  <span>{log.action.replaceAll("_", " ")}</span>
                  <span>{log.model_route}</span>
                  <small>{log.created_at}</small>
                </button>
              ))}
            </div>
          </Panel>

          <Panel title="Architecture & Compliance" icon={KeyRound} className="span3">
            <div className="architecture">
              {docs.architecture.map((item) => (
                <div key={item}>
                  <span>{item}</span>
                  <ChevronRight size={15} />
                </div>
              ))}
            </div>
            <div className="compliance">
              {docs.compliance.map((item) => <Badge key={item}>{item}</Badge>)}
            </div>
          </Panel>

          <Panel title="Notifications & SIEM" icon={Bell} className="span3">
            <div className="integrationGrid">
              {["Slack", "Microsoft Teams", "Email", "Webhook", "Splunk", "Microsoft Sentinel", "Elastic", "QRadar", "Chronicle"].map((item) => (
                <article key={item}>
                  <strong>{item}</strong>
                  <span>Ready for critical prompt and repeated violation events</span>
                </article>
              ))}
            </div>
          </Panel>
        </section>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")).render(<App />);
