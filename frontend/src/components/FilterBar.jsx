function FilterBar({
  severity,
  setSeverity,
  risk,
  setRisk,
  attackType,
  setAttackType,
}) {
  return (
    <div className="mb-6 grid gap-4 md:grid-cols-3">
      <select
        value={severity}
        onChange={(e) => setSeverity(e.target.value)}
        className="rounded-lg border border-slate-700 bg-slate-900 p-3 text-white"
      >
        <option value="">All Severities</option>
        <option>CRITICAL</option>
        <option>HIGH</option>
        <option>MEDIUM</option>
        <option>LOW</option>
      </select>

      <select
        value={risk}
        onChange={(e) => setRisk(e.target.value)}
        className="rounded-lg border border-slate-700 bg-slate-900 p-3 text-white"
      >
        <option value="">All Risk Levels</option>
        <option>Critical</option>
        <option>High</option>
        <option>Medium</option>
        <option>Low</option>
      </select>

      <select
        value={attackType}
        onChange={(e) => setAttackType(e.target.value)}
        className="rounded-lg border border-slate-700 bg-slate-900 p-3 text-white"
      >
        <option value="">All Attack Types</option>
        <option>Brute Force</option>
        <option>Path Traversal</option>
      </select>
    </div>
  );
}

export default FilterBar;