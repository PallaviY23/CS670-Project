import { useEffect, useRef, useState } from "react";
import { buildStarterInput } from "../../src/prover/inputs.js";
import { createProverClient } from "../../src/prover/worker-client.js";
import {
  Activity,
  ArrowDownRight,
  ArrowRight,
  Check,
  CircleAlert,
  CircleCheck,
  Fingerprint,
  FileCheck2,
  Gauge,
  KeyRound,
  LockKeyhole,
  Network,
  RotateCcw,
  ShieldCheck,
  Sparkles,
  Building2,
  RefreshCw,
  Ban,
  Clock,
  Database,
} from "lucide-react";

const initialHealth = { status: "checking", proofReady: false };
const stageLabels = {
  artifacts: "Loading proving artifacts",
  witness: "Computing witness",
  proof: "Generating Groth16 proof",
  verify: "Verifying with service provider",
};

async function createReceiptId(proof, publicSignals) {
  const payload = new TextEncoder().encode(JSON.stringify({ proof, publicSignals }));
  const digest = await crypto.subtle.digest("SHA-256", payload);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 12)
    .toUpperCase();
}

function App() {
  const [activeTab, setActiveTab] = useState("workspace"); // "workspace" | "sp-view"
  const [health, setHealth] = useState(initialHealth);
  const [age, setAge] = useState(21);
  const [kycVerified, setKycVerified] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [receipt, setReceipt] = useState(null);
  const [stage, setStage] = useState("artifacts");
  const proverRef = useRef(null);

  useEffect(() => () => proverRef.current?.terminate(), []);

  // Service Provider (Task S9) state
  const [spRequest, setSpRequest] = useState(null);
  const [spLoading, setSpLoading] = useState(false);
  const [spAuditEntries, setSpAuditEntries] = useState([]);
  const [spVerifyResult, setSpVerifyResult] = useState(null);
  const [revocationRoot, setRevocationRoot] = useState(null);
  const [revokeInputId, setRevokeInputId] = useState("1001");
  const [revokeMsg, setRevokeMsg] = useState("");

  useEffect(() => {
    let active = true;
    fetch("/api/health")
      .then((response) => response.json())
      .then((payload) => {
        if (active) {
          setHealth({ ...payload, status: "online" });
          if (payload.revocationRoot) setRevocationRoot(payload.revocationRoot);
        }
      })
      .catch(() => {
        if (active) setHealth({ status: "offline", proofReady: false });
      });

    loadAuditLog();

    return () => {
      active = false;
    };
  }, []);

  async function loadAuditLog() {
    try {
      const res = await fetch("/api/sp/audit-log");
      if (res.ok) {
        const data = await res.json();
        setSpAuditEntries(data.entries ?? []);
      }
    } catch {
      // ignore offline errors
    }
  }

  async function requestSpChallenge() {
    setSpLoading(true);
    setSpVerifyResult(null);
    try {
      const res = await fetch("/api/sp/request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ spId: "123456789", minAgeOffset: 180000 }),
      });
      const data = await res.json();
      setSpRequest(data);
    } catch (err) {
      alert("Failed to request challenge from Service Provider.");
    } finally {
      setSpLoading(false);
    }
  }

  async function handleRevokeCredential(e) {
    e.preventDefault();
    if (!revokeInputId) return;
    try {
      const res = await fetch("/api/revocation/revoke", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ credentialId: revokeInputId }),
      });
      const data = await res.json();
      if (res.ok) {
        setRevokeMsg(`Credential ${revokeInputId} revoked! New Root: ${data.newRoot?.slice(0, 16)}...`);
        setRevocationRoot(data.newRoot);
      } else {
        setRevokeMsg(`Error: ${data.error}`);
      }
    } catch (err) {
      setRevokeMsg(`Request failed: ${err.message}`);
    }
  }

  async function handleSubmit(event) {
    event.preventDefault();
    if (!health.proofReady || busy) return;

    setBusy(true);
    setError("");
    setReceipt(null);
    setStage("artifacts");

    try {
      const input = buildStarterInput({ age, kycVerified });
      proverRef.current ??= createProverClient();
      const { proof, publicSignals, timings, proofBytes } = await proverRef.current.prove(input, { onProgress: setStage });
      setStage("verify");
      const [receiptId, verificationResponse] = await Promise.all([
        createReceiptId(proof, publicSignals),
        fetch("/api/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ proof, publicSignals }),
        }),
      ]);
      const verification = await verificationResponse.json();

      if (!verificationResponse.ok) {
        throw new Error(verification.error ?? "The verifier could not process this proof.");
      }

      setReceipt({ ...verification, ...timings, proofBytes: proofBytes.raw, receiptId });
    } catch (caughtError) {
      setError(caughtError instanceof Error ? caughtError.message : "Proof generation failed.");
    } finally {
      setBusy(false);
    }
  }

  function resetDemo() {
    setReceipt(null);
    setError("");
  }

  const apiLabel = health.status === "online" ? "API online" : health.status === "offline" ? "API offline" : "Connecting";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#top" aria-label="Private KYC Proof Lab home">
          <span className="brand-mark"><Fingerprint size={20} strokeWidth={1.8} /></span>
          <span className="brand-name">FIELDNOTE<span> / KYC LAB</span></span>
        </a>

        <div className="sidebar-label">WORKSPACE</div>
        <nav className="side-nav" aria-label="Workspace sections">
          <button
            type="button"
            className={`side-link ${activeTab === "workspace" ? "active" : ""}`}
            onClick={() => setActiveTab("workspace")}
            style={{ border: 0, textAlign: "left", width: "100%", cursor: "pointer" }}
          >
            <KeyRound size={16} />Proof workspace
          </button>
          <button
            type="button"
            className={`side-link ${activeTab === "sp-view" ? "active" : ""}`}
            onClick={() => {
              setActiveTab("sp-view");
              loadAuditLog();
            }}
            style={{ border: 0, textAlign: "left", width: "100%", cursor: "pointer" }}
          >
            <Building2 size={16} />Service Provider (SP)
          </button>
          <a className="side-link" href="#proof-flow"><Network size={16} />Proof flow</a>
          <a className="side-link" href="#team"><Activity size={16} />Build status</a>
        </nav>

        <div className="sidebar-spacer" />
        <div className="privacy-note">
          <div className="privacy-note-icon"><LockKeyhole size={17} /></div>
          <p>Private by design</p>
          <span>Witness stays in this browser. The verifier receives only proof data.</span>
        </div>
        <div className="sidebar-foot"><span className="live-dot" />LOCAL PROTOTYPE <span className="mono">v0.1</span></div>
      </aside>

      <main id="top" className="main-area">
        <header className="topbar">
          <div className="breadcrumb">
            <span>PROJECT</span>
            <ArrowRight size={13} />
            <strong>{activeTab === "sp-view" ? "Service Provider Portal (Apex Bank)" : "Proof lab"}</strong>
          </div>
          <div className="topbar-status">
            <span className={`api-indicator ${health.status}`} />
            <span>{apiLabel}</span>
            <span className="topbar-divider" />
            <span className="env-tag">DEV ENVIRONMENT</span>
          </div>
        </header>

        <div className="page-content">
          {activeTab === "sp-view" ? (
            /* --- SERVICE PROVIDER DEMO VIEW (Task S9) --- */
            <section className="sp-section">
              <div className="page-intro">
                <div className="intro-copy">
                  <div className="eyebrow"><span className="eyebrow-line" />SERVICE PROVIDER VIEW (APEX FINANCIAL)</div>
                  <h1>High-Yield Account<br /><em>Compliance Verification</em></h1>
                  <p className="intro-description">
                    The relying party requests compliance proofs (Age ≥ 18 and Active KYC) without ever receiving
                    the customer&apos;s date of birth, name, or raw government identity documents.
                  </p>
                </div>
                <div className="intro-side-note">
                  <span className="side-note-index">SP ID: 123456789</span>
                  <p>Fail-closed verifier pipeline with single-use challenges & nullifiers.</p>
                  <div className="mini-claims"><span>ANTI-REPLAY</span><span>REVOCATION AWARE</span><span>ZERO ATTRIBUTES LOGGED</span></div>
                </div>
              </div>

              {/* Step 1: Request Challenge */}
              <div className="sp-card">
                <div className="sp-card-header">
                  <div>
                    <div className="section-kicker">STEP 01 / CHALLENGE ISSUANCE</div>
                    <h3>Anti-Replay Nonce & Policy</h3>
                  </div>
                  <button className="sp-btn" onClick={requestSpChallenge} disabled={spLoading}>
                    <RefreshCw size={14} className={spLoading ? "spin" : ""} />
                    {spRequest ? "Refresh Challenge" : "Issue New Proof Request"}
                  </button>
                </div>
                <p className="panel-subtitle">
                  The service provider generates an ephemeral random scalar field challenge with a 5-minute TTL.
                </p>

                {spRequest ? (
                  <div className="challenge-box">
                    <div className="challenge-field"><span>REQUEST ID</span><strong>{spRequest.requestId}</strong></div>
                    <div className="challenge-field"><span>RANDOM NONCE (Fr)</span><strong>{spRequest.challenge}</strong></div>
                    <div className="challenge-field"><span>SERVICE PROVIDER ID</span><strong>{spRequest.spId}</strong></div>
                    <div className="challenge-field"><span>SERVER DATE</span><strong>{spRequest.currentDate}</strong></div>
                    <div className="challenge-field"><span>MIN AGE OFFSET</span><strong>{spRequest.minAgeOffset} (≥ 18 years)</strong></div>
                    <div className="challenge-field"><span>EXPIRES AT</span><strong>{spRequest.expiresAt}</strong></div>
                  </div>
                ) : (
                  <div style={{ color: "#77857b", fontSize: "11px", fontStyle: "italic" }}>
                    Click &ldquo;Issue New Proof Request&rdquo; to generate an anti-replay challenge from POST /api/sp/request.
                  </div>
                )}
              </div>

              {/* Step 2: Revocation Registry State */}
              <div className="sp-card">
                <div className="sp-card-header">
                  <div>
                    <div className="section-kicker">REVOCATION REGISTRY / POSEIDON MERKLE TREE</div>
                    <h3>Active Credential Management (Task S6)</h3>
                  </div>
                  <span className="mono" style={{ fontSize: "11px", color: "#365e49" }}>DEPTH 16 (65,536 LEAVES)</span>
                </div>
                <div className="challenge-box">
                  <div className="challenge-field">
                    <span>CURRENT REVOCATION ROOT</span>
                    <strong>{revocationRoot ?? "Initialized"}</strong>
                  </div>
                </div>

                <form onSubmit={handleRevokeCredential} style={{ display: "flex", gap: "10px", alignItems: "center", marginTop: "12px" }}>
                  <label htmlFor="revoke-id" style={{ fontSize: "11px", color: "#4f5f55" }}>Revoke Credential ID:</label>
                  <input
                    id="revoke-id"
                    type="text"
                    value={revokeInputId}
                    onChange={(e) => setRevokeInputId(e.target.value)}
                    style={{ padding: "6px 10px", border: "1px solid #cfd8cd", borderRadius: "4px", fontFamily: "var(--mono)", fontSize: "12px" }}
                  />
                  <button type="submit" className="sp-btn-secondary">
                    <Ban size={14} color="#a4473c" /> Revoke Immediately
                  </button>
                  {revokeMsg && <span style={{ fontSize: "11px", color: "#3a5647" }}>{revokeMsg}</span>}
                </form>
              </div>

              {/* Step 3: Privacy-Preserving Audit Log */}
              <div className="sp-card">
                <div className="sp-card-header">
                  <div>
                    <div className="section-kicker">TASK S7 / PRIVACY-COMPLIANT AUDIT LOG</div>
                    <h3>Verification Audit Log</h3>
                  </div>
                  <button className="sp-btn-secondary" onClick={loadAuditLog}>
                    <RefreshCw size={12} /> Refresh Log
                  </button>
                </div>
              ) : busy ? (
                <div className="verifying-state">
                  <span className="large-spinner" />
                  <h3>Building a proof</h3>
                  <p>Your witness is being processed locally. No age value leaves this tab.</p>
                  <div className="progress-track"><span /></div>
                  <span className="mono progress-caption">{stageLabels[stage]?.toUpperCase()} · GROTH16 · BN128</span>
                </div>
              </section>

              <div className="prototype-banner">
                <CircleAlert size={17} />
                <p><strong>Prototype boundary</strong> The KYC status is currently a simulated private input, not an issuer-signed credential.</p>
                <a href="#proof-flow">See the flow <ArrowRight size={13} /></a>
              </div>

              <section className="workspace-grid" aria-label="Proof generation workspace">
                <form className="panel request-panel" onSubmit={handleSubmit}>
                  <div className="panel-heading">
                    <div>
                      <div className="section-kicker">01 / PRIVATE WITNESS</div>
                      <h2>Set up a claim</h2>
                    </div>
                    <span className="panel-icon"><Fingerprint size={18} /></span>
                  </div>
                  <div className="signal-heading"><span>PUBLIC SIGNALS</span><span>RESULT</span></div>
                  <div className="signal-row"><span>isAdult</span><strong className={receipt.claims?.ageAtLeast18 ? "signal-pass" : "signal-fail"}>{receipt.claims?.ageAtLeast18 ? "1 · PASS" : "0 · FAIL"}</strong></div>
                  <div className="signal-row"><span>isVerified</span><strong className={receipt.claims?.kycVerified ? "signal-pass" : "signal-fail"}>{receipt.claims?.kycVerified ? "1 · PASS" : "0 · FAIL"}</strong></div>
                  <div className="receipt-metrics">
                    <div><span>WITNESS TIME</span><strong>{receipt.witnessMs} <small>ms</small></strong></div>
                    <div><span>PROVE TIME</span><strong>{receipt.provingMs} <small>ms</small></strong></div>
                    <div><span>VERIFY TIME</span><strong>{receipt.verificationMs} <small>ms</small></strong></div>
                    <div><span>PROOF SIZE</span><strong>{receipt.proofBytes} <small>B</small></strong></div>
                  </div>
                  <div className="field-hint"><LockKeyhole size={13} /> Age is not sent to the API.</div>

                  <div className="field-label kyc-label">Credential status <span className="simulated-label">SIMULATED</span></div>
                  <label className="toggle-row" htmlFor="kyc-verified">
                    <span className="toggle-copy"><strong>KYC verified</strong><small>Private circuit input for this demo</small></span>
                    <input id="kyc-verified" type="checkbox" checked={kycVerified} onChange={(event) => setKycVerified(event.target.checked)} />
                    <span className="toggle-track" aria-hidden="true"><span /></span>
                  </label>

                  <div className="claim-summary">
                    <div><span className="summary-dot" /><span>Claim 01</span><strong>Age ≥ 18</strong></div>
                    <div><span className="summary-dot" /><span>Claim 02</span><strong>KYC verified</strong></div>
                  </div>

                  {!health.proofReady && (
                    <div className="setup-hint">
                      <CircleAlert size={15} />
                      <span>{health.status === "offline" ? "Start the API, then reload." : "Run npm run setup:demo to create local proving keys."}</span>
                    </div>
                  )}
                  {error && <div className="error-message" role="alert"><CircleAlert size={15} />{error}</div>}

                  <button className="primary-button" type="submit" disabled={!health.proofReady || busy || age === ""}>
                    {busy ? <><span className="spinner" />Generating proof locally</> : <><Sparkles size={16} />Generate & verify<ArrowRight size={15} /></>}
                  </button>
                  <div className="button-footnote"><span className="live-dot" />{health.proofReady ? "Proof setup ready" : "Proof setup not initialized"}</div>
                </form>

                <section className={`panel receipt-panel ${receipt ? (receipt.accepted ? "accepted" : "not-accepted") : ""}`} aria-live="polite">
                  <div className="panel-heading">
                    <div>
                      <div className="section-kicker">02 / SERVICE PROVIDER</div>
                      <h2>Verification receipt</h2>
                    </div>
                    <span className="panel-icon receipt-icon">{receipt?.accepted ? <CircleCheck size={19} /> : receipt ? <CircleAlert size={19} /> : <ShieldCheck size={19} />}</span>
                  </div>

                  {!receipt && !busy ? (
                    <div className="empty-receipt">
                      <div className="empty-art"><div className="art-ring ring-one" /><div className="art-ring ring-two" /><ShieldCheck size={34} strokeWidth={1.2} /></div>
                      <h3>Awaiting proof</h3>
                      <p>When verification completes, the result and public claim signals will appear here.</p>
                      <div className="empty-state-rule"><span /><span>NO PROOF DATA RECEIVED</span><span /></div>
                    </div>
                  ) : busy ? (
                    <div className="verifying-state">
                      <span className="large-spinner" />
                      <h3>Building a proof</h3>
                      <p>Your witness is being processed locally. No age value leaves this tab.</p>
                      <div className="progress-track"><span /></div>
                      <span className="mono progress-caption">GROTH16 · BN128</span>
                    </div>
                  ) : (
                    <div className="receipt-content">
                      <div className={`receipt-outcome ${receipt.accepted ? "success" : "failure"}`}>
                        {receipt.accepted ? <CircleCheck size={21} /> : <CircleAlert size={21} />}
                        <div><strong>{receipt.accepted ? "Claims verified" : receipt.proofValid ? "Proof valid · claim not met" : "Proof rejected"}</strong><span>{receipt.accepted ? "Service provider may proceed" : "The requested condition was not satisfied"}</span></div>
                      </div>
                      <div className="signal-heading"><span>PUBLIC SIGNALS</span><span>RESULT</span></div>
                      <div className="signal-row"><span>isAdult</span><strong className={receipt.claims?.ageAtLeast18 ? "signal-pass" : "signal-fail"}>{receipt.claims?.ageAtLeast18 ? "1 · PASS" : "0 · FAIL"}</strong></div>
                      <div className="signal-row"><span>isVerified</span><strong className={receipt.claims?.kycVerified ? "signal-pass" : "signal-fail"}>{receipt.claims?.kycVerified ? "1 · PASS" : "0 · FAIL"}</strong></div>
                      <div className="receipt-metrics">
                        <div><span>PROVE TIME</span><strong>{receipt.provingMs} <small>ms</small></strong></div>
                        <div><span>VERIFY TIME</span><strong>{receipt.verificationMs} <small>ms</small></strong></div>
                        <div><span>PROOF SIZE</span><strong>{(receipt.proofBytes / 1024).toFixed(2)} <small>KB</small></strong></div>
                      </div>
                      <div className="receipt-id"><span>LOCAL RECEIPT ID</span><code>{receipt.receiptId}</code></div>
                      <button className="reset-button" type="button" onClick={resetDemo}><RotateCcw size={14} />Reset demo</button>
                    </div>
                  )}
                </section>
              </section>
            </>
          )}

          <section className="flow-section" id="proof-flow">
            <div className="section-heading-row">
              <div><div className="section-kicker">HOW THIS DEMO WORKS</div><h2>Data stays with its owner.</h2></div>
              <span className="mono section-meta">LOCAL PROTOTYPE / GROTH16</span>
            </div>
            <div className="flow-grid">
              <article className="flow-step"><span className="flow-number">01</span><div className="flow-icon"><FileCheck2 size={18} /></div><h3>Private inputs</h3><p>Age and the simulated KYC flag are entered in the browser.</p><span className="flow-tag private-tag">PRIVATE WITNESS</span></article>
              <div className="flow-connector"><ArrowRight size={16} /></div>
              <article className="flow-step"><span className="flow-number">02</span><div className="flow-icon"><KeyRound size={18} /></div><h3>Local proof</h3><p>SnarkJS creates a Groth16 proof without uploading the witness.</p><span className="flow-tag">CLIENT-SIDE</span></article>
              <div className="flow-connector"><ArrowRight size={16} /></div>
              <article className="flow-step"><span className="flow-number">03</span><div className="flow-icon"><ShieldCheck size={18} /></div><h3>Proof check</h3><p>The API verifies the proof and reads only the public claim outputs.</p><span className="flow-tag">PROOF + SIGNALS</span></article>
            </div>
          </section>

          <section className="build-section" id="team">
            <div className="section-heading-row build-heading">
              <div><div className="section-kicker">TEAM MODULES</div><h2>Built in parallel.</h2></div>
              <div className="build-badge"><Gauge size={15} />BASE PROTOTYPE</div>
            </div>
            <div className="team-grid">
              <div className="team-item"><span className="team-index">P</span><span><strong>Credential design</strong><small>Commitments & selective disclosure</small></span><span className="team-state">IN PROGRESS</span></div>
              <div className="team-item"><span className="team-index">V</span><span><strong>Circuit & claims</strong><small>Age range & KYC status constraints</small></span><span className="team-state state-ready"><Check size={12} /> BASE READY</span></div>
              <div className="team-item"><span className="team-index">D</span><span><strong>Prover pipeline</strong><small>Browser proving & performance</small></span><span className="team-state">IN PROGRESS</span></div>
              <div className="team-item"><span className="team-index">S</span><span><strong>Verifier & security</strong><small>Public inputs, anti-replay & attacks</small></span><span className="team-state state-ready"><Check size={12} /> DELIVERED</span></div>
            </div>
          </section>

          <footer className="page-footer"><span>CS670 PROJECT · PRIVACY-PRESERVING DIGITAL KYC</span><span>SOMESHWAR SINGH (231020) · VERIFICATION & SECURITY</span><a href="#top" aria-label="Back to top"><ArrowDownRight size={15} /></a></footer>
        </div>
      </main>
    </div>
  );
}

export default App;
