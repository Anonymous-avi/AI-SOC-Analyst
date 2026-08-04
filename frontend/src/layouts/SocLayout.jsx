import { ArrowRight, ShieldAlert } from "lucide-react";

function SocLayout({
  title,
  subtitle,
  eyebrow = "AI SOC Analyst",
  navItems = [],
  actions,
  theme,
  onToggleTheme,
  children,
}) {
  return (
    <div className="soc-shell">
      <div className="floating-particles" aria-hidden="true" />
      <span className="ambient-orb one" aria-hidden="true" />
      <span className="ambient-orb two" aria-hidden="true" />
      <span className="ambient-orb three" aria-hidden="true" />

      <aside className="soc-sidebar glass-panel">
        <div className="soc-brand">
          <span className="soc-logo">
            <ShieldAlert size={20} />
          </span>

          <div>
            <p className="soc-brand-title">AI SOC Analyst</p>
            <p className="soc-brand-subtitle">Enterprise Security Operations</p>
          </div>
        </div>

        <div className="status-pill">
          <span className="h-2 w-2 rounded-full bg-emerald-400" />
          Production Monitoring
        </div>

        <nav className="soc-nav">
          {navItems.map((item) => {
            const Icon = item.icon;

            return (
              <a key={item.label} href={item.href} className="soc-nav-item">
                {Icon ? <Icon size={16} /> : null}
                <span>{item.label}</span>
                <ArrowRight className="ml-auto opacity-60" size={14} />
              </a>
            );
          })}
        </nav>

        <div className="soc-sidebar-footer">
          <button type="button" onClick={onToggleTheme} className="theme-toggle">
            <span>{theme === "dark" ? "Dark Mode" : "Light Mode"}</span>
            <span className="badge">Toggle</span>
          </button>

          <p className="section-subtitle">
            Glassmorphism, threat telemetry, and incident response tools tuned for SOC teams.
          </p>
        </div>
      </aside>

      <div className="soc-content">
        <header className="soc-topbar glass-panel">
          <div className="flex flex-wrap items-start justify-between gap-6">
            <div className="max-w-3xl">
              <div className="hero-eyebrow">{eyebrow}</div>

              <h1 className="hero-title mt-4">{title}</h1>

              <p className="hero-description mt-4">{subtitle}</p>
            </div>

            <div className="detail-actions">{actions}</div>
          </div>
        </header>

        <main className="soc-main">{children}</main>
      </div>
    </div>
  );
}

export default SocLayout;