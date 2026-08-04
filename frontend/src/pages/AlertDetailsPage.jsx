import { useEffect, useState } from "react";
import {
  ArrowLeft,
  Download,
  ShieldAlert,
  Sparkles,
  TriangleAlert,
} from "lucide-react";
import { useNavigate, useParams } from "react-router-dom";

import { fetchAlertById } from "../api/alertsApi";
import AISummaryCard from "../components/AISummaryCard";
import { downloadReport } from "../api/reportsApi";
import SocLayout from "../layouts/SocLayout";
import { useTheme } from "../hooks/useTheme";


function AlertDetailsPage() {
  const { alertId } = useParams();
  const navigate = useNavigate();
  const { theme, toggleTheme } = useTheme();

  const [alert, setAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");


  useEffect(() => {
    async function loadAlert() {
      try {
        const data = await fetchAlertById(alertId);
        setAlert(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    loadAlert();
  }, [alertId]);

  const navItems = [
    { label: "Back to Dashboard", href: "/" , icon: ArrowLeft },
    { label: "MITRE", href: "#mitre", icon: ShieldAlert },
    { label: "IOCs", href: "#iocs", icon: TriangleAlert },
    { label: "AI Summary", href: "#summary", icon: Sparkles },
  ];


  if (loading) {
    return (
      <SocLayout
        title="Alert Investigation"
        subtitle="Loading incident evidence, summary intelligence, and remediation guidance."
        navItems={navItems}
        theme={theme}
        onToggleTheme={toggleTheme}
      >
        <div className="loading-skeleton">
          <div className="detail-card">
            <div className="skeleton h-5 w-40" />
            <div className="skeleton mt-4 h-12 w-72" />
            <div className="mt-6 grid gap-4 md:grid-cols-3">
              {[...Array(3)].map((_, index) => (
                <div key={index} className="skeleton h-24 w-full" />
              ))}
            </div>
          </div>
        </div>
      </SocLayout>
    );
  }


  if (error || !alert) {
    return (
      <SocLayout
        title="Alert Investigation"
        subtitle="The selected incident could not be loaded."
        navItems={navItems}
        theme={theme}
        onToggleTheme={toggleTheme}
      >
        <div className="empty-state">
          <p className="section-title text-red-400">{error || "Alert not found"}</p>
          <p className="section-subtitle">
            Return to the dashboard or retry the alert lookup.
          </p>

          <button
            onClick={() => navigate("/")}
            className="primary-button"
          >
            Back to Dashboard
          </button>
        </div>
      </SocLayout>
    );
  }


  return (
    <SocLayout
      title="Alert Investigation"
      subtitle={`Focused incident review for ${alert.alert_id}.`}
      navItems={navItems}
      theme={theme}
      onToggleTheme={toggleTheme}
      actions={
        <>
          <button
            onClick={() => navigate("/")}
            className="secondary-button"
          >
            <ArrowLeft size={16} />
            Back
          </button>

          <button
            onClick={() => downloadReport(alert.alert_id)}
            className="primary-button"
          >
            <Download size={16} />
            Export PDF
          </button>
        </>
      }
    >
      <section className="detail-card">
        <div className="flex flex-wrap items-start justify-between gap-6">
          <div>
            <div className="hero-eyebrow">Incident Overview</div>
            <h2 className="hero-title mt-4">{alert.title}</h2>
            <p className="hero-description mt-4">{alert.alert_id}</p>
          </div>

          <div className="detail-actions">
            <span className="badge">{alert.attack_type}</span>
            <span className="badge">{alert.severity}</span>
            <span className="badge">{alert.risk_level}</span>
            <span className="badge">Score {alert.threat_score}</span>
          </div>
        </div>

        <div className="mt-8 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <InfoItem label="Attack Type" value={alert.attack_type} />
          <InfoItem label="Severity" value={alert.severity} />
          <InfoItem label="Risk Level" value={alert.risk_level} />
          <InfoItem label="Threat Score" value={alert.threat_score} />
          <InfoItem label="Confidence" value={`${Math.round((alert.confidence ?? 0) * 100)}%`} />
          <InfoItem label="Attacker IP" value={alert.attacker_ip || "Unknown"} />
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-2" id="mitre">
        <SectionCard title="MITRE ATT&CK Mapping">
          <InfoItem label="Tactic" value={alert.mitre?.tactic} />
          <InfoItem label="Technique" value={alert.mitre?.technique} />
          <InfoItem label="Technique ID" value={alert.mitre?.technique_id} />
        </SectionCard>

        <SectionCard title="Recommended Action">
          <p className="leading-7 text-[var(--text-soft)]">{alert.recommendation}</p>
        </SectionCard>
      </section>

      <section id="summary">
        <AISummaryCard alertId={alert.alert_id} />
      </section>

      <section className="section-grid two-up" id="iocs">
        <SectionCard title="Indicators of Compromise">
          <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
            <IOCList label="IP Addresses" values={alert.iocs?.ips} />
            <IOCList label="Domains" values={alert.iocs?.domains} />
            <IOCList label="URLs" values={alert.iocs?.urls} />
            <IOCList label="CVEs" values={alert.iocs?.cves} />
            <IOCList label="Hashes" values={alert.iocs?.hashes} />
            <IOCList label="Malware" values={alert.iocs?.malware} />
          </div>
        </SectionCard>

        <SectionCard title="Threat Intelligence">
          {alert.threat_intelligence?.length ? (
            <div className="space-y-4">
              {alert.threat_intelligence.map((intel, index) => (
                <div
                  key={`${intel.indicator}-${index}`}
                  className="hero-metric"
                >
                  <div>
                    <p className="hero-metric-label">{intel.indicator}</p>
                    <p className="hero-metric-note">
                      {intel.provider} · {intel.reputation}
                    </p>
                  </div>

                  <span className="badge">
                    {intel.malicious ? "Malicious" : "Benign"}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="section-subtitle">No threat intelligence data available.</p>
          )}
        </SectionCard>
      </section>

      {alert.metadata && Object.keys(alert.metadata).length ? (
        <SectionCard title="ML Signals">
          <div className="grid gap-4 md:grid-cols-2">
            <InfoItem
              label="Detection Engine"
              value={alert.metadata.model_votes ? "Hybrid anomaly ensemble" : "Standard rules"}
            />
            <InfoItem
              label="Confidence"
              value={
                alert.metadata.anomaly_confidence ?? alert.confidence
              }
            />
            {Array.isArray(alert.metadata.top_contributing_factors) ? (
              <div className="md:col-span-2">
                <p className="mb-2 text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-muted)]">
                  Top Contributing Factors
                </p>

                <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
                  {alert.metadata.top_contributing_factors.map((factor) => (
                    <div
                      key={factor.feature}
                      className="rounded-2xl border border-[var(--border)] bg-white/5 px-3 py-2 text-sm text-[var(--text-soft)]"
                    >
                      {factor.feature}
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        </SectionCard>
      ) : null}
    </SocLayout>
  );
}


function SectionCard({ title, children }) {
  return (
    <section className="section-card">
      <h2 className="section-title mb-5">
        {title}
      </h2>

      <div className="space-y-4">
        {children}
      </div>
    </section>
  );
}


function InfoItem({ label, value }) {
  return (
    <div>
      <p className="text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-muted)]">
        {label}
      </p>

      <p className="mt-1 break-words text-[var(--text)]">
        {value ?? "Not available"}
      </p>
    </div>
  );
}


function IOCList({ label, values = [] }) {
  return (
    <div>
      <p className="mb-2 text-xs font-medium uppercase tracking-[0.18em] text-[var(--text-muted)]">
        {label}
      </p>

      {values?.length ? (
        <div className="space-y-2">
          {values.map((value) => (
            <div
              key={value}
              className="break-all rounded-2xl border border-[var(--border)] bg-white/5 px-3 py-2 text-sm text-[var(--text-soft)]"
            >
              {value}
            </div>
          ))}
        </div>
      ) : (
        <p className="text-sm text-[var(--text-muted)]">
          None detected
        </p>
      )}
    </div>
  );
}


export default AlertDetailsPage;