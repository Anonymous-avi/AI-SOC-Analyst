import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";

const COLORS = [
  "#38bdf8",
  "#f97316",
  "#ef4444",
  "#22c55e",
  "#a855f7",
];

function AttackTypeChart({ alerts }) {
  const attackMap = {};

  alerts.forEach((alert) => {
    attackMap[alert.attack_type] =
      (attackMap[alert.attack_type] || 0) + 1;
  });

  const data = Object.keys(attackMap).map((key) => ({
    name: key,
    value: attackMap[key],
  }));

  return (
    <div className="chart-card">
      <div className="chart-card-header">
        <div>
          <h2 className="section-title">Attack Types</h2>
          <p className="section-subtitle">Observed attack families in the uploaded data.</p>
        </div>
      </div>

      <ResponsiveContainer width="100%" height={300}>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            outerRadius={100}
            label
          >
            {data.map((entry, index) => (
              <Cell
                key={index}
                fill={COLORS[index % COLORS.length]}
              />
            ))}
          </Pie>

          <Tooltip
            contentStyle={{
              borderRadius: 16,
              border: "1px solid var(--border)",
              background: "var(--bg-elevated)",
              color: "var(--text)",
            }}
          />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export default AttackTypeChart;