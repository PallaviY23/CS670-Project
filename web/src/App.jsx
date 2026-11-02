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
  const [health, setHealth] = useState(initialHealth);
  const [age, setAge] = useState(21);
  const [kycVerified, setKycVerified] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [receipt, setReceipt] = useState(null);
  const [stage, setStage] = useState("artifacts");
  const proverRef = useRef(null);

  useEffect(() => () => proverRef.current?.terminate(), []);

  useEffect(() => {
    let active = true;
    fetch("/api/health")
      .then((response) => response.json())
      .then((payload) => {
        if (active) setHealth({ ...payload, status: "online" });
      })
      .catch(() => {
        if (active) setHealth({ status: "offline", proofReady: false });
      });

    return () => {
      active = false;
    };
  }, []);

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
          <a className="side-link active" href="#proof-workspace"><KeyRound size={16} />Proof workspace</a>
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
          <div className="breadcrumb"><span>PROJECT</span><ArrowRight size={13} /><strong>Proof lab</strong></div>
          <div className="topbar-status">
            <span className={`api-indicator ${health.status}`} />
            <span>{apiLabel}</span>
            <span className="topbar-divider" />
            <span className="env-tag">DEV ENVIRONMENT</span>
          </div>
        </header>

        <div className="page-content">
          <section className="page-intro" id="proof-workspace">
            <div className="intro-copy">
              <div className="eyebrow"><span className="eyebrow-line" />ZERO-KNOWLEDGE DEMONSTRATION</div>
              <h1>Prove the claim.<br /><em>Keep the identity.</em></h1>
              <p className="intro-description">Show that a KYC requirement is met without handing over the information behind it.</p>
            </div>
            <div className="intro-side-note">
              <span className="side-note-index">01 / 03</span>
              <p>One proof. Two claims.<br />No personal data in the request.</p>
              <div className="mini-claims"><span>AGE ≥ 18</span><span>KYC VERIFIED</span></div>
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
              <p className="panel-subtitle">These values are used in your browser to build the proof.</p>

              <label className="field-label" htmlFor="age">Your age <span>PRIVATE</span></label>
              <div className="age-input-wrap">
                <input id="age" name="age" type="number" min="0" max="255" required value={age} onChange={(event) => setAge(event.target.value)} />
                <span>years</span>
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
                  <span className="mono progress-caption">{stageLabels[stage]?.toUpperCase()} · GROTH16 · BN128</span>
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
                    <div><span>WITNESS TIME</span><strong>{receipt.witnessMs} <small>ms</small></strong></div>
                    <div><span>PROVE TIME</span><strong>{receipt.provingMs} <small>ms</small></strong></div>
                    <div><span>VERIFY TIME</span><strong>{receipt.verificationMs} <small>ms</small></strong></div>
                    <div><span>PROOF SIZE</span><strong>{receipt.proofBytes} <small>B</small></strong></div>
                  </div>
                  <div className="receipt-id"><span>LOCAL RECEIPT ID</span><code>{receipt.receiptId}</code></div>
                  <button className="reset-button" type="button" onClick={resetDemo}><RotateCcw size={14} />Reset demo</button>
                </div>
              )}
            </section>
          </section>

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
              <div className="team-item"><span className="team-index">S</span><span><strong>Verifier & security</strong><small>Public inputs & tamper testing</small></span><span className="team-state">IN PROGRESS</span></div>
            </div>
          </section>

          <footer className="page-footer"><span>CS670 PROJECT · PRIVACY-PRESERVING DIGITAL KYC</span><span>DEMO ONLY · NO CREDENTIAL ISSUER INTEGRATION</span><a href="#top" aria-label="Back to top"><ArrowDownRight size={15} /></a></footer>
        </div>
      </main>
    </div>
  );
}

export default App;