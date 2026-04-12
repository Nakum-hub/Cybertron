const MILESTONES = [
  {
    phase: 'Phase 1',
    title: 'Trustworthy Launch Baseline',
    timeline: '0-30 days',
    glowColor: 'rgba(52, 211, 153, 0.15)',
    outcomes: [
      'Production-grade landing and auth foundation',
      'Quality, security, and release operating model active',
    ],
  },
  {
    phase: 'Phase 2',
    title: 'Enterprise Expansion',
    timeline: '31-90 days',
    glowColor: 'rgba(0, 240, 255, 0.15)',
    outcomes: [
      'Live integrations for telemetry and control workflows',
      'Regionalized governance and analytics for growth',
    ],
  },
  {
    phase: 'Phase 3',
    title: 'Global Platform Scale',
    timeline: '90+ days',
    glowColor: 'rgba(168, 85, 247, 0.15)',
    outcomes: [
      'Multi-product operating shell with unified trust services',
      'Executive reliability and security KPIs at board level',
    ],
  },
];

export default function ExecutionSection() {
  return (
    <section id="execution" className="py-16 sm:py-20 px-0 holo-divider bg-[#070910]">
      <div className="section-wrap">
        <header className="mb-10 sm:mb-12 max-w-3xl reveal-up">
          <p className="section-kicker mb-2">Company Execution Plan</p>
          <h2 className="section-title text-3xl sm:text-5xl mb-4">
            From Startup Velocity To Global Leadership
          </h2>
          <p className="section-copy">
            Cross-functional execution led by product, engineering, security, design, quality, and
            growth teams with measurable milestones.
          </p>
        </header>

        <div className="grid gap-6 lg:grid-cols-3">
          {MILESTONES.map((item, index) => (
            <article
              key={item.phase}
              className={`panel-3d rounded-2xl p-6 reveal-up ${
                index === 1 ? 'reveal-delay-1' : index === 2 ? 'reveal-delay-2' : ''
              }`}
              style={{ boxShadow: `0 0 0px ${item.glowColor}` }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLElement).style.boxShadow = `0 0 60px ${item.glowColor}, 0 0 100px ${item.glowColor}`;
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLElement).style.boxShadow = `0 0 0px ${item.glowColor}`;
              }}
            >
              <div className="mb-4 flex items-center justify-between gap-2">
                <p className="text-xs text-cyan-300 uppercase tracking-[0.16em]">{item.phase}</p>
                <span className="text-xs text-slate-300">{item.timeline}</span>
              </div>
              <h3 className="text-lg font-semibold mb-1">{item.title}</h3>

              <ul className="space-y-2">
                {item.outcomes.map(outcome => (
                  <li key={outcome} className="text-sm text-slate-200 leading-relaxed">
                    <span className="text-cyan-300 mr-2">*</span>
                    {outcome}
                  </li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

