import { useEffect, useState } from "react";
import { ArrowLeft, ShieldAlert } from "lucide-react";
import { useNavigate, useParams } from "react-router-dom";

import { fetchAlertById } from "../api/alertsApi";
import AISummaryCard from "../components/AISummaryCard";


function AlertDetailsPage() {
  const { alertId } = useParams();
  const navigate = useNavigate();

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


  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950 text-slate-300">
        Loading alert investigation...
      </div>
    );
  }


  if (error || !alert) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-slate-950 text-white">
        <p className="text-red-400">
          {error || "Alert not found"}
        </p>

        <button
          onClick={() => navigate("/")}
          className="rounded-lg bg-slate-800 px-4 py-2 hover:bg-slate-700"
        >
          Back to Dashboard
        </button>
      </div>
    );
  }


  return (
    <main className="min-h-screen bg-slate-950 text-white">
      <header className="border-b border-slate-800 px-8 py-5">
        <div className="mx-auto flex max-w-7xl items-center gap-4">
          <button
            onClick={() => navigate("/")}
            className="rounded-lg border border-slate-800 p-2 text-slate-400 hover:bg-slate-900 hover:text-white"
          >
            <ArrowLeft className="h-5 w-5" />
          </button>

          <ShieldAlert className="h-8 w-8 text-cyan-400" />

          <div>
            <h1 className="text-2xl font-bold">
              Alert Investigation
            </h1>

            <p className="text-sm text-slate-500">
              {alert.alert_id}
            </p>
          </div>
        </div>
      </header>


      <section className="mx-auto max-w-7xl space-y-6 p-8">

        <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
          <h2 className="text-2xl font-bold">
            {alert.title}
          </h2>

          <div className="mt-6 grid gap-6 md:grid-cols-2 lg:grid-cols-4">
            <InfoItem
              label="Attack Type"
              value={alert.attack_type}
            />

            <InfoItem
              label="Severity"
              value={alert.severity}
            />

            <InfoItem
              label="Risk Level"
              value={alert.risk_level}
            />

            <InfoItem
              label="Threat Score"
              value={alert.threat_score}
            />

            <InfoItem
              label="Confidence"
              value={`${Math.round(alert.confidence * 100)}%`}
            />

            <InfoItem
              label="Attacker IP"
              value={alert.attacker_ip || "Unknown"}
            />
          </div>
        </div>


        <div className="grid gap-6 lg:grid-cols-2">

          <SectionCard title="MITRE ATT&CK">
            <InfoItem
              label="Tactic"
              value={alert.mitre?.tactic}
            />

            <InfoItem
              label="Technique"
              value={alert.mitre?.technique}
            />

            <InfoItem
              label="Technique ID"
              value={alert.mitre?.technique_id}
            />
          </SectionCard>


          <SectionCard title="Recommended Action">
            <p className="leading-7 text-slate-300">
              {alert.recommendation}
            </p>
          </SectionCard>

        </div>
        <AISummaryCard alertId={alert.alert_id} />


        <SectionCard title="Indicators of Compromise">
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            <IOCList
              label="IP Addresses"
              values={alert.iocs?.ips}
            />

            <IOCList
              label="Domains"
              values={alert.iocs?.domains}
            />

            <IOCList
              label="URLs"
              values={alert.iocs?.urls}
            />

            <IOCList
              label="CVEs"
              values={alert.iocs?.cves}
            />

            <IOCList
              label="Hashes"
              values={alert.iocs?.hashes}
            />

            <IOCList
              label="Malware"
              values={alert.iocs?.malware}
            />
          </div>
        </SectionCard>


        <SectionCard title="Threat Intelligence">
          {alert.threat_intelligence?.length ? (
            <div className="space-y-4">
              {alert.threat_intelligence.map(
                (intel, index) => (
                  <div
                    key={`${intel.indicator}-${index}`}
                    className="rounded-lg border border-slate-800 bg-slate-950 p-4"
                  >
                    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                      <InfoItem
                        label="Indicator"
                        value={intel.indicator}
                      />

                      <InfoItem
                        label="Reputation"
                        value={intel.reputation}
                      />

                      <InfoItem
                        label="Malicious"
                        value={intel.malicious ? "Yes" : "No"}
                      />

                      <InfoItem
                        label="Provider"
                        value={intel.provider}
                      />
                    </div>
                  </div>
                )
              )}
            </div>
          ) : (
            <p className="text-slate-500">
              No threat intelligence data available.
            </p>
          )}
        </SectionCard>

      </section>
    </main>
  );
}


function SectionCard({ title, children }) {
  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900 p-6">
      <h2 className="mb-5 text-lg font-semibold">
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
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
        {label}
      </p>

      <p className="mt-1 break-words text-slate-200">
        {value ?? "Not available"}
      </p>
    </div>
  );
}


function IOCList({ label, values = [] }) {
  return (
    <div>
      <p className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
        {label}
      </p>

      {values?.length ? (
        <div className="space-y-2">
          {values.map((value) => (
            <div
              key={value}
              className="break-all rounded-lg bg-slate-950 px-3 py-2 text-sm text-slate-300"
            >
              {value}
            </div>
          ))}
        </div>
      ) : (
        <p className="text-sm text-slate-600">
          None detected
        </p>
      )}
    </div>
  );
}


export default AlertDetailsPage;