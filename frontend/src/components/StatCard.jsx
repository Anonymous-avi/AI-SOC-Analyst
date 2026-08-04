function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  tone = "primary",
  className = "",
}) {
  return (
    <div className={`metric-card alert-gradient-border metric-card--large tone-${tone} ${className}`.trim()}>
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="metric-label">{title}</p>

          <p className="metric-value">{value}</p>
        </div>

        {Icon ? (
          <span className={`metric-icon tone-${tone}`}>
            <Icon size={20} />
          </span>
        ) : null}
      </div>

      <p className="metric-subtitle">
        {subtitle}
      </p>
    </div>
  );
}

export default StatCard;