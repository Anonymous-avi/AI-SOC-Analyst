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
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
      <h2 className="mb-4 text-lg font-semibold text-white">
        Threat Score Distribution
      </h2>

      <ResponsiveContainer width="100%" height={320}>
        <BarChart data={ranges}>
          <XAxis dataKey="range" stroke="#94a3b8" />
          <YAxis stroke="#94a3b8" />
          <Tooltip />
          <Bar
            dataKey="count"
            fill="#22c55e"
            radius={[6, 6, 0, 0]}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export default ThreatScoreChart;