import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

function SeverityChart({ alerts }) {
  const severityCount = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0,
  };

  alerts.forEach((alert) => {
    if (severityCount[alert.severity] !== undefined) {
      severityCount[alert.severity]++;
    }
  });

  const data = [
    { severity: "LOW", count: severityCount.LOW },
    { severity: "MEDIUM", count: severityCount.MEDIUM },
    { severity: "HIGH", count: severityCount.HIGH },
    { severity: "CRITICAL", count: severityCount.CRITICAL },
  ];

  return (
    <div className="rounded-xl bg-slate-900 p-6 border border-slate-800">
      <h2 className="mb-4 text-lg font-semibold text-white">
        Alerts by Severity
      </h2>

      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={data}>
          <XAxis dataKey="severity" stroke="#94a3b8" />
          <YAxis stroke="#94a3b8" />
          <Tooltip />
          <Bar dataKey="count" fill="#38bdf8" radius={[6, 6, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export default SeverityChart;