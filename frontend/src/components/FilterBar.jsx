function FilterBar({
  severity,
  setSeverity,
  risk,
  setRisk,
  attackType,
  setAttackType,
}) {
  return (
    <div className="toolbar-grid">
      <select
        value={severity}
        onChange={(e) => setSeverity(e.target.value)}
        className="select-field"
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
        className="select-field"
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
        className="select-field"
      >
        <option value="">All Attack Types</option>
        <option>Brute Force</option>
        <option>Path Traversal</option>
        <option>SQL Injection</option>
        <option>XSS</option>
        <option>Command Injection</option>
        <option>Port Scanning</option>
      </select>
    </div>
  );
}

export default FilterBar;