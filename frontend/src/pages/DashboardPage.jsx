import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  FileText,
  Globe2,
  Radar,
  RefreshCw,
  ShieldAlert,
  Siren,
  Sparkles,
  TriangleAlert,
} from "lucide-react";

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
import SocLayout from "../layouts/SocLayout";
import { useTheme } from "../hooks/useTheme";

function DashboardPage() {
  const { theme, toggleTheme } = useTheme();

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [searchTerm, setSearchTerm] = useState("");

  const [severity, setSeverity] = useState("");

  const [risk, setRisk] = useState("");

  const [attackType, setAttackType] = useState("");
  const [currentPage, setCurrentPage] = useState(1);

  const navItems = [
    { label: "Overview", href: "#overview", icon: Activity },
    { label: "Threat Intel", href: "#threat-intel", icon: Radar },
    { label: "Alerts", href: "#alerts", icon: TriangleAlert },
    { label: "Reports", href: "#reports", icon: FileText },
  ];

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

useEffect(() => {
    loadAlerts();
}, []);

  const sortedAlerts = useMemo(
    () =>
      [...alerts].sort((left, right) => {
        const leftScore = Number(left?.threat_score ?? 0);
        const rightScore = Number(right?.threat_score ?? 0);

        return rightScore - leftScore;
      }),
    [alerts]
  );

  const filteredAlerts = useMemo(() => {
    return sortedAlerts.filter((alert) => {
      const searchValue = searchTerm.trim().toLowerCase();

      const matchesSearch =
        !searchValue ||
        [
          alert.alert_id,
          alert.attacker_ip,
          alert.attack_type,
          alert.title,
        ]
          .filter(Boolean)
          .some((value) =>
            String(value).toLowerCase().includes(searchValue)
          );

      const matchesSeverity =
        severity === "" ||
        String(alert.severity ?? "").toUpperCase() === severity;

      const matchesRisk =
        risk === "" ||
        String(alert.risk_level ?? "").toLowerCase() ===
          risk.toLowerCase();

      const matchesAttack =
        attackType === "" || alert.attack_type === attackType;

      return (
        matchesSearch &&
        matchesSeverity &&
        matchesRisk &&
        matchesAttack
      );
    });
  }, [attackType, risk, searchTerm, severity, sortedAlerts]);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchTerm, severity, risk, attackType]);

  const dashboardStats = useMemo(() => {
    const totalAlerts = alerts.length;
    const criticalAlerts = filteredAlerts.filter(
      (alert) => String(alert.risk_level ?? "").toLowerCase() === "critical"
    ).length;
    const highAlerts = filteredAlerts.filter(
      (alert) => String(alert.risk_level ?? "").toLowerCase() === "high"
    ).length;
    const averageThreatScore = filteredAlerts.length
      ? Math.round(
          filteredAlerts.reduce(
            (total, alert) => total + Number(alert.threat_score ?? 0),
            0
          ) / filteredAlerts.length
        )
      : 0;
    const activeThreats = filteredAlerts.filter(
      (alert) => Number(alert.threat_score ?? 0) >= 70
    ).length;
    const uniqueIps = new Set(
      filteredAlerts.map((alert) => alert.attacker_ip).filter(Boolean)
    ).size;
    const iocVolume = filteredAlerts.reduce((count, alert) => {
      const iocs = alert.iocs ?? {};

      return (
        count +
        [iocs.ips, iocs.domains, iocs.urls, iocs.cves, iocs.hashes, iocs.malware]
          .flat()
          .filter(Boolean).length
      );
    }, 0);

    return {
      totalAlerts,
      criticalAlerts,
      highAlerts,
      averageThreatScore,
      activeThreats,
      uniqueIps,
      iocVolume,
    };
  }, [alerts.length, filteredAlerts]);

  const topAttackers = useMemo(() => {
    const attackerMap = new Map();

    filteredAlerts.forEach((alert) => {
      if (!alert.attacker_ip) {
        return;
      }

      attackerMap.set(
        alert.attacker_ip,
        (attackerMap.get(alert.attacker_ip) ?? 0) + 1
      );
    });

    return [...attackerMap.entries()]
      .sort((left, right) => right[1] - left[1])
      .slice(0, 5)
      .map(([ip, count]) => ({ ip, count }));
  }, [filteredAlerts]);

  const recentActivity = filteredAlerts.slice(0, 5);

  const currentPageCount = Math.max(
    1,
    Math.ceil(filteredAlerts.length / 5)
  );

  const paginatedAlerts = filteredAlerts.slice(
    (currentPage - 1) * 5,
    currentPage * 5
  );


  if (loading) {
    return (
      <SocLayout
        title="Security Operations Dashboard"
        subtitle="Loading intelligence, alerts, and threat analytics."
        navItems={navItems}
        theme={theme}
        onToggleTheme={toggleTheme}
      >
        <div className="loading-skeleton">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {[...Array(4)].map((_, index) => (
              <div key={index} className="metric-card">
                <div className="skeleton h-4 w-32" />
                <div className="skeleton mt-6 h-10 w-24" />
                <div className="skeleton mt-4 h-3 w-48" />
              </div>
            ))}
          </div>

          <div className="section-grid two-up">
            <div className="chart-card">
              <div className="skeleton h-6 w-44" />
              <div className="skeleton mt-6 h-[300px] w-full" />
            </div>

            <div className="chart-card">
              <div className="skeleton h-6 w-44" />
              <div className="skeleton mt-6 h-[300px] w-full" />
            </div>
          </div>
        </div>
      </SocLayout>
    );
  }


  if (error) {
    return (
      <SocLayout
        title="Security Operations Dashboard"
        subtitle="The alerting pipeline could not be loaded."
        navItems={navItems}
        theme={theme}
        onToggleTheme={toggleTheme}
      >
        <div className="empty-state">
          <div>
            <p className="section-title text-red-400">Unable to load alerts</p>
            <p className="section-subtitle">{error}</p>
          </div>

          <button onClick={loadAlerts} className="primary-button">
            Retry
          </button>
        </div>
      </SocLayout>
    );
  }


  return (
    <SocLayout
      title="Security Operations Dashboard"
      subtitle="Monitor uploads, enriched alerts, and attack patterns in one command center."
      navItems={navItems}
      theme={theme}
      onToggleTheme={toggleTheme}
      actions={
        <>
          <button onClick={loadAlerts} className="secondary-button">
            <RefreshCw size={16} />
            Refresh
          </button>

          <button className="primary-button">
            <Sparkles size={16} />
            AI Summary
          </button>
        </>
      }
    >
      <section id="overview" className="dashboard-grid aurora-layout">
        <div className="hero-copy card-surface metric-card--hero">
          <span className="hex-badge">
            <ShieldAlert size={22} />
          </span>

          <div className="hero-eyebrow">
            <ShieldAlert size={14} />
            LIVE SECURITY OPERATIONS
          </div>

          <div>
            <h2 className="hero-title">
              Enterprise-grade visibility for SOC analysts.
            </h2>

            <p className="hero-description mt-4">
              Correlate detections, investigate suspicious activity, and triage incidents with a premium console built for security teams.
            </p>
          </div>

          <div className="hero-actions">
            <span className="badge">MongoDB Atlas</span>
            <span className="badge">FastAPI</span>
            <span className="badge">MITRE ATT&amp;CK</span>
            <span className="badge">Threat Intel Ready</span>
          </div>

          <UploadLogs onUploadSuccess={loadAlerts} />
        </div>

        <div className="glass-panel hero-metrics metric-card--tall">
          <div className="hero-metric">
            <div>
              <p className="hero-metric-label">Total Alerts</p>
              <p className="hero-metric-value">{dashboardStats.totalAlerts}</p>
              <p className="hero-metric-note">Stored security incidents</p>
            </div>

            <Activity className="text-cyan-300" />
          </div>

          <div className="hero-metric">
            <div>
              <p className="hero-metric-label">Active Threats</p>
              <p className="hero-metric-value">{dashboardStats.activeThreats}</p>
              <p className="hero-metric-note">Score above 70 or immediate review required</p>
            </div>

            <ShieldAlert className="text-violet-300" />
          </div>

          <div className="hero-metric">
            <div>
              <p className="hero-metric-label">Critical Alerts</p>
              <p className="hero-metric-value">{dashboardStats.criticalAlerts}</p>
              <p className="hero-metric-note">Escalated to incident handling</p>
            </div>

            <Siren className="text-rose-300" />
          </div>
        </div>
      </section>

      <section className="dashboard-mosaic" id="metrics">
        <StatCard
          title="Total Alerts"
          value={dashboardStats.totalAlerts}
          subtitle="Stored security incidents"
          icon={Activity}
          tone="primary"
          className="metric-card--hero"
        />

        <StatCard
          title="Critical Alerts"
          value={dashboardStats.criticalAlerts}
          subtitle="Requires immediate attention"
          icon={Siren}
          tone="danger"
          className="metric-card--large"
        />

        <StatCard
          title="High Risk Alerts"
          value={dashboardStats.highAlerts}
          subtitle="High priority incidents"
          icon={TriangleAlert}
          tone="warning"
          className="metric-card--large"
        />

        <StatCard
          title="Average Threat Score"
          value={dashboardStats.averageThreatScore}
          subtitle="Across the active filtered set"
          icon={ShieldAlert}
          tone="success"
          className="metric-card--large"
        />
      </section>

      <section className="dashboard-grid aurora-layout" id="threats">
          <StatCard
            title="Unique Attackers"
            value={dashboardStats.uniqueIps}
            subtitle="Distinct attacker IPs in the current view"
            icon={Globe2}
            tone="primary"
            className="metric-card--wide"
          />

          <StatCard
            title="IOC Volume"
            value={dashboardStats.iocVolume}
            subtitle="Indicators extracted from filtered alerts"
            icon={Radar}
            tone="success"
            className="metric-card--large"
          />
      </section>

      <section className="section-grid two-up" id="reports">
        <SeverityChart alerts={filteredAlerts} />
        <AttackTypeChart alerts={filteredAlerts} />
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <ThreatScoreChart alerts={filteredAlerts} />

        <div className="chart-card" id="threat-intel">
          <div className="chart-card-header">
            <div>
              <h2 className="section-title">Threat Intelligence Panel</h2>
              <p className="section-subtitle">
                Integration architecture for VirusTotal, AbuseIPDB, OTX, GreyNoise, and MISP.
              </p>
            </div>
          </div>

          <div className="grid gap-3">
            {[
              ["VirusTotal", "Hash, URL, and domain reputation"],
              ["AbuseIPDB", "IP reputation and abuse history"],
              ["AlienVault OTX", "Pulse-based IOC enrichment"],
              ["GreyNoise", "Internet noise and scanner context"],
              ["MISP", "Threat sharing and correlation"],
            ].map(([name, description]) => (
              <div key={name} className="hero-metric">
                <div>
                  <p className="hero-metric-label">{name}</p>
                  <p className="hero-metric-note">{description}</p>
                </div>

                <span className="badge">Ready</span>
              </div>
            ))}
          </div>

          <div className="mt-5 rounded-2xl border border-[var(--border)] bg-white/5 p-4">
            <p className="section-title">Top Attacking IPs</p>
            <div className="mt-4 grid gap-3">
              {topAttackers.length ? (
                topAttackers.map((attacker) => (
                  <div key={attacker.ip} className="hero-metric">
                    <div>
                      <p className="hero-metric-label">{attacker.ip}</p>
                      <p className="hero-metric-note">{attacker.count} observed alerts</p>
                    </div>
                    <ArrowUpRight size={18} className="text-cyan-300" />
                  </div>
                ))
              ) : (
                <p className="section-subtitle">No attacker IPs available yet.</p>
              )}
            </div>
          </div>
        </div>
      </section>

      <section className="toolbar card-surface" id="alerts">
        <div className="chart-card-header">
          <div>
            <h2 className="section-title">Search and Filter Alerts</h2>
            <p className="section-subtitle">
              Narrow incidents by severity, risk, or attack family.
            </p>
          </div>

          <span className="badge">{filteredAlerts.length} results</span>
        </div>

        <SearchBar searchTerm={searchTerm} setSearchTerm={setSearchTerm} />
        <FilterBar
          severity={severity}
          setSeverity={setSeverity}
          risk={risk}
          setRisk={setRisk}
          attackType={attackType}
          setAttackType={setAttackType}
        />
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.3fr_0.7fr]">
        <div className="space-y-6">
          <AlertTable alerts={paginatedAlerts} />

          <Pagination
            currentPage={currentPage}
            totalPages={currentPageCount}
            setCurrentPage={setCurrentPage}
          />
        </div>

        <div className="chart-card">
          <div className="chart-card-header">
            <div>
              <h2 className="section-title">Recent Activity</h2>
              <p className="section-subtitle">
                Latest alerts surfaced by the detection engine.
              </p>
            </div>
          </div>

          <div className="grid gap-3">
            {recentActivity.length ? (
              recentActivity.map((alert) => (
                <div key={alert.alert_id} className="hero-metric">
                  <div>
                    <p className="hero-metric-label">{alert.title}</p>
                    <p className="hero-metric-note">
                      {alert.attack_type} · {alert.attacker_ip ?? "Unknown IP"}
                    </p>
                  </div>

                  <span className="badge">{alert.threat_score}</span>
                </div>
              ))
            ) : (
              <div className="empty-state">
                <p className="section-title">No recent activity</p>
                <p className="section-subtitle">Upload logs to generate detections.</p>
              </div>
            )}
          </div>
        </div>
      </section>
    </SocLayout>
  );
}

export default DashboardPage;