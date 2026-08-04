import { useNavigate } from "react-router-dom";


function getRiskClasses(riskLevel) {
  switch (riskLevel?.toLowerCase()) {
    case "critical":
      return "bg-red-500/15 text-red-400";

    case "high":
      return "bg-orange-500/15 text-orange-400";

    case "medium":
      return "bg-yellow-500/15 text-yellow-400";

    default:
      return "bg-emerald-500/15 text-emerald-400";
  }
}


function getSeverityClass(severity) {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "severity-chip severity-critical";

    case "high":
      return "severity-chip severity-high";

    case "medium":
      return "severity-chip severity-medium";

    default:
      return "severity-chip severity-low";
  }
}


function AlertTable({ alerts }) {
  const navigate = useNavigate();

  if (!alerts.length) {
    return (
      <div className="empty-state">
        <div>
          <p className="section-title">No alerts match the current filters</p>
          <p className="section-subtitle">
            Try broadening the search or upload a fresh log set to generate new detections.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="table-card overflow-hidden p-0">
      <div className="table-card-header px-6 pt-6">
        <div>
          <h2 className="section-title">Recent Security Alerts</h2>
          <p className="section-subtitle">
            Click any incident to open the investigation workspace.
          </p>
        </div>

        <span className="badge">{alerts.length} visible</span>
      </div>

      <div className="overflow-x-auto">
        <table className="alert-table">
          <thead>
            <tr>
              <th className="px-6 py-4">Timestamp</th>
              <th className="px-6 py-4">Alert</th>
              <th className="px-6 py-4">Attacker IP</th>
              <th className="px-6 py-4">Attack Type</th>
              <th className="px-6 py-4">Severity</th>
              <th className="px-6 py-4">Threat Score</th>
              <th className="px-6 py-4">Risk</th>
            </tr>
          </thead>

          <tbody>
            {alerts.map((alert) => (
              <tr
                key={alert.alert_id}
                onClick={() =>
                  navigate(
                    `/alerts/${encodeURIComponent(
                      alert.alert_id
                    )}`
                  )
                }
                className="alert-row cursor-pointer text-sm"
              >
                <td className="px-6 py-4 text-[var(--text-muted)]">
                  {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : "Recent"}
                </td>

                <td className="px-6 py-4">
                  <p className="font-medium text-[var(--text)]">
                    {alert.title}
                  </p>

                  <p className="mt-1 text-xs text-[var(--text-muted)]">
                    {alert.alert_id}
                  </p>
                </td>

                <td className="px-6 py-4 text-[var(--text-soft)]">
                  {alert.attacker_ip ?? "Unknown"}
                </td>

                <td className="px-6 py-4 text-[var(--text-soft)]">
                  {alert.attack_type}
                </td>

                <td className="px-6 py-4">
                  <span className={getSeverityClass(alert.severity)}>
                    {alert.severity}
                  </span>
                </td>

                <td className="px-6 py-4 font-semibold text-[var(--text)]">
                  {alert.threat_score}
                </td>

                <td className="px-6 py-4">
                  <span
                    className={`risk-chip ${getRiskClasses(
                      alert.risk_level
                    )}`}
                  >
                    {alert.risk_level}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}


export default AlertTable;