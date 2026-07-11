import { useEffect, useState } from "react";
import { Activity, ShieldAlert, Siren, TriangleAlert } from "lucide-react";

import { fetchAlerts } from "../api/alertsApi";
import AlertTable from "../components/AlertTable";
import StatCard from "../components/StatCard";


function DashboardPage() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");


  useEffect(() => {
    async function loadAlerts() {
      try {
        const data = await fetchAlerts();
        setAlerts(data);
      } catch (err) {
        console.error(err);
        setError("Failed to load security alerts.");
      } finally {
        setLoading(false);
      }
    }

    loadAlerts();
  }, []);


  const criticalAlerts = alerts.filter(
    (alert) => alert.risk_level?.toLowerCase() === "critical"
  ).length;

  const highAlerts = alerts.filter(
    (alert) => alert.risk_level?.toLowerCase() === "high"
  ).length;

  const averageThreatScore = alerts.length
    ? Math.round(
        alerts.reduce(
          (total, alert) => total + alert.threat_score,
          0
        ) / alerts.length
      )
    : 0;


  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950 text-slate-300">
        Loading SOC dashboard...
      </div>
    );
  }


  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950 text-red-400">
        {error}
      </div>
    );
  }


  return (
    <main className="min-h-screen bg-slate-950 text-white">
      <header className="border-b border-slate-800 bg-slate-950 px-8 py-5">
        <div className="mx-auto max-w-7xl">
          <div className="flex items-center gap-3">
            <ShieldAlert className="h-8 w-8 text-cyan-400" />

            <div>
              <h1 className="text-2xl font-bold">
                AI SOC Analyst
              </h1>

              <p className="text-sm text-slate-500">
                Security Operations Intelligence Dashboard
              </p>
            </div>
          </div>
        </div>
      </header>


      <section className="mx-auto max-w-7xl p-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold">
            Security Overview
          </h2>

          <p className="mt-2 text-slate-400">
            Real-time visibility into detected threats and security alerts.
          </p>
        </div>


        <div className="mb-8 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <StatCard
            title="Total Alerts"
            value={alerts.length}
            subtitle="Stored security incidents"
            icon={Activity}
          />

          <StatCard
            title="Critical Alerts"
            value={criticalAlerts}
            subtitle="Requires immediate attention"
            icon={Siren}
          />

          <StatCard
            title="High Risk Alerts"
            value={highAlerts}
            subtitle="High priority incidents"
            icon={TriangleAlert}
          />

          <StatCard
            title="Average Threat Score"
            value={averageThreatScore}
            subtitle="Across all detected alerts"
            icon={ShieldAlert}
          />
        </div>


        <AlertTable alerts={alerts} />
      </section>
    </main>
  );
}

export default DashboardPage;