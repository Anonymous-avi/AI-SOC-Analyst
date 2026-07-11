function StatCard({ title, value, subtitle }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
      <p className="text-sm font-medium text-slate-400">
        {title}
      </p>

      <p className="mt-2 text-3xl font-bold text-white">
        {value}
      </p>

      <p className="mt-2 text-xs text-slate-500">
        {subtitle}
      </p>
    </div>
  );
}

export default StatCard;