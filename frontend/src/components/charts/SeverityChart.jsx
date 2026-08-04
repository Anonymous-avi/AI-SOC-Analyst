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
    <div className="chart-card">
      <div className="chart-card-header">
        <div>
          <h2 className="section-title">Alerts by Severity</h2>
          <p className="section-subtitle">Priority distribution across the current result set.</p>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={data}>
          <XAxis dataKey="severity" stroke="var(--text-muted)" />
          <YAxis stroke="var(--text-muted)" />
          <Tooltip
            contentStyle={{
              borderRadius: 16,
              border: "1px solid var(--border)",
              background: "var(--bg-elevated)",
              color: "var(--text)",
            }}
          />
          <Bar dataKey="count" fill="#38bdf8" radius={[8, 8, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export default SeverityChart;
