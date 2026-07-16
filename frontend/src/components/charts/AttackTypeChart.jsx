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
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
      <h2 className="mb-4 text-lg font-semibold text-white">
        Attack Types
      </h2>

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

          <Tooltip />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export default AttackTypeChart;