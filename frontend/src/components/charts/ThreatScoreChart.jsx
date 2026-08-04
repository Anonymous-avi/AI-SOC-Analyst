import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

function ThreatScoreChart({ alerts }) {
  const ranges = [
    { range: "0-20", count: 0 },
    { range: "21-40", count: 0 },
    { range: "41-60", count: 0 },
    { range: "61-80", count: 0 },
    { range: "81-100", count: 0 },
  ];

  alerts.forEach((alert) => {
    const score = alert.threat_score;

    if (score <= 20) ranges[0].count++;
    else if (score <= 40) ranges[1].count++;
    else if (score <= 60) ranges[2].count++;
    else if (score <= 80) ranges[3].count++;
    else ranges[4].count++;
  });

  return (
    <div className="chart-card">
      <div className="chart-card-header">
        <div>
          <h2 className="section-title">Threat Score Distribution</h2>
          <p className="section-subtitle">Higher bars indicate more incidents in that score band.</p>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={320}>
        <BarChart data={ranges}>
          <XAxis dataKey="range" stroke="var(--text-muted)" />
          <YAxis stroke="var(--text-muted)" />
          <Tooltip
            contentStyle={{
              borderRadius: 16,
              border: "1px solid var(--border)",
              background: "var(--bg-elevated)",
              color: "var(--text)",
            }}
          />
          <Bar
            dataKey="count"
            fill="#22c55e"
            radius={[8, 8, 0, 0]}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export default ThreatScoreChart;