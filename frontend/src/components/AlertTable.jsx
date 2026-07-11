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


function AlertTable({ alerts }) {
  const navigate = useNavigate();

  return (
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
      <div className="border-b border-slate-800 px-6 py-4">
        <h2 className="text-lg font-semibold text-white">
          Recent Security Alerts
        </h2>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead className="bg-slate-950/50 text-xs uppercase text-slate-500">
            <tr>
              <th className="px-6 py-4">Alert</th>
              <th className="px-6 py-4">Attacker IP</th>
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
                className="cursor-pointer border-t border-slate-800 text-sm transition hover:bg-slate-800/60"
              >
                <td className="px-6 py-4">
                  <p className="font-medium text-white">
                    {alert.title}
                  </p>

                  <p className="mt-1 text-xs text-slate-500">
                    {alert.alert_id}
                  </p>
                </td>

                <td className="px-6 py-4 text-slate-300">
                  {alert.attacker_ip ?? "Unknown"}
                </td>

                <td className="px-6 py-4 text-slate-300">
                  {alert.severity}
                </td>

                <td className="px-6 py-4 font-semibold text-white">
                  {alert.threat_score}
                </td>

                <td className="px-6 py-4">
                  <span
                    className={`rounded-full px-3 py-1 text-xs font-semibold ${getRiskClasses(
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