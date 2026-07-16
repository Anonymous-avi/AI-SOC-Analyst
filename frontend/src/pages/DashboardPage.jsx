import { useEffect, useState } from "react";
import { Activity, ShieldAlert, Siren, TriangleAlert } from "lucide-react";

import { fetchAlerts } from "../api/alertsApi";
import AlertTable from "../components/AlertTable";
import StatCard from "../components/StatCard";

import SeverityChart from "../components/charts/SeverityChart";
import AttackTypeChart from "../components/charts/AttackTypeChart";
import ThreatScoreChart from "../components/charts/ThreatScoreChart";
import UploadLogs from "../components/UploadLogs";

import SearchBar from "../components/SearchBar";
import FilterBar from "../components/FilterBar";
import Pagination from "../components/Pagination";

function DashboardPage() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [searchTerm, setSearchTerm] = useState("");

  const [severity, setSeverity] = useState("");

  const [risk, setRisk] = useState("");

  const [attackType, setAttackType] = useState("");
  const [currentPage, setCurrentPage] = useState(1);

  async function loadAlerts() {
    try {
        setLoading(true);

        const data = await fetchAlerts();

        setAlerts(data);
    } catch (err) {
        console.error(err);
        setError("Failed to load security alerts.");
    } finally {
        setLoading(false);
    }
}
const filteredAlerts = alerts.filter((alert) => {
  const matchesSearch =
    alert.alert_id
      ?.toLowerCase()
      .includes(searchTerm.toLowerCase()) ||
    alert.attacker_ip
      ?.toLowerCase()
      .includes(searchTerm.toLowerCase()) ||
    alert.attack_type
      ?.toLowerCase()
      .includes(searchTerm.toLowerCase());

  const matchesSeverity =
    severity === "" ||
    alert.severity === severity;

  const matchesRisk =
    risk === "" ||
    alert.risk_level === risk;

  const matchesAttack =
    attackType === "" ||
    alert.attack_type === attackType;

  return (
    matchesSearch &&
    matchesSeverity &&
    matchesRisk &&
    matchesAttack
  );
});
const alertsPerPage = 5;

const totalPages = Math.ceil(
  filteredAlerts.length / alertsPerPage
);

const paginatedAlerts = filteredAlerts.slice(
  (currentPage - 1) * alertsPerPage,
  currentPage * alertsPerPage
);

useEffect(() => {
    loadAlerts();
}, []);

  const criticalAlerts = filteredAlerts.filter(
  (alert) => alert.risk_level?.toLowerCase() === "critical"
  ).length;

  const highAlerts = filteredAlerts.filter(
  (alert) => alert.risk_level?.toLowerCase() === "high"
).length;

  const averageThreatScore = filteredAlerts.length
    ? Math.round(
        filteredAlerts.reduce(
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
      <UploadLogs
        onUploadSuccess={loadAlerts}
       />
       </div>
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


        <div className="grid gap-6 lg:grid-cols-2 mb-8">
         <SeverityChart alerts={filteredAlerts} />
         <AttackTypeChart alerts={filteredAlerts} />
        </div>

        <div className="mb-8">
        <ThreatScoreChart alerts={filteredAlerts} />
        </div>

<SearchBar
  searchTerm={searchTerm}
  setSearchTerm={setSearchTerm}
/>

<FilterBar
  severity={severity}
  setSeverity={setSeverity}
  risk={risk}
  setRisk={setRisk}
  attackType={attackType}
  setAttackType={setAttackType}
/>

<>
  <AlertTable alerts={paginatedAlerts} />

  <Pagination
    currentPage={currentPage}
    totalPages={totalPages}
    setCurrentPage={setCurrentPage}
  />
</>
      </section>
    </main>
  );
}

export default DashboardPage;