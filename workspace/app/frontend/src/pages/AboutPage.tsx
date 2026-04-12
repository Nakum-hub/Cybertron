import { ArrowLeft, Users, Shield, Globe, Zap } from 'lucide-react';
import { Link } from 'react-router-dom';

const TEAM = [
    { name: 'Platform Engineering', count: '1', focus: 'Full-Stack Architecture & Security Infrastructure' },
    { name: 'Open Source', count: '∞', focus: 'Community Contributions Welcome' },
    { name: 'Mission', count: '100%', focus: 'Enterprise Cyber Ops for Everyone' },
];

const VALUES = [
    { icon: Shield, title: 'Security First', desc: 'Every line of code we write is designed with zero-trust principles and auditability in mind.' },
    { icon: Globe, title: 'Enterprise Ready', desc: 'Tenant-aware architecture, RBAC, and compliance-grade audit logs from day one.' },
    { icon: Zap, title: 'Real Telemetry', desc: 'No fabricated signals. Every metric and incident in Cybertron reflects truthful operational data.' },
    { icon: Users, title: 'Customer Obsessed', desc: 'Built for security teams who need reliable tools, not flashy demos with mocked data.' },
];

export default function AboutPage() {
    return (
        <div className="min-h-screen bg-[#0A0A0F] text-white">
            <div className="max-w-4xl mx-auto px-4 sm:px-6 py-16 sm:py-24">
                <Link
                    to="/"
                    className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-cyan-300 transition-colors mb-12"
                >
                    <ArrowLeft className="w-4 h-4" />
                    Back to Home
                </Link>

                <div className="mb-16">
                    <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-cyan-500/20 bg-cyan-500/5 mb-6">
                        <Users className="w-3.5 h-3.5 text-cyan-400" />
                        <span className="text-cyan-300 text-xs font-semibold tracking-widest uppercase">About Us</span>
                    </div>
                    <h1 className="text-4xl sm:text-5xl font-bold mb-6">
                        Building the Future of{' '}
                        <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                            Cyber Operations
                        </span>
                    </h1>
                    <p className="text-lg text-slate-400 leading-relaxed max-w-3xl">
                        Cybertron is an enterprise cyber operations platform built by a solo engineer
                        with a vision: real-time incident response, compliance workflows, and threat
                        intelligence should be accessible to organizations of every size — built in the open,
                        not behind a paywall.
                    </p>
                </div>

                <div className="mb-16">
                    <h2 className="text-2xl font-bold mb-8">Our Values</h2>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                        {VALUES.map(v => (
                            <div key={v.title} className="p-6 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                                <v.icon className="w-8 h-8 text-cyan-400 mb-4" />
                                <h3 className="text-lg font-semibold text-white mb-2">{v.title}</h3>
                                <p className="text-sm text-slate-400 leading-relaxed">{v.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="mb-16">
                    <h2 className="text-2xl font-bold mb-8">Our Team</h2>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
                        {TEAM.map(t => (
                            <div key={t.name} className="p-6 rounded-xl bg-white/[0.03] border border-white/[0.06] text-center">
                                <div className="text-3xl font-extrabold text-cyan-400 mb-2">{t.count}</div>
                                <div className="text-white font-semibold mb-1">{t.name}</div>
                                <p className="text-xs text-slate-500">{t.focus}</p>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="p-8 rounded-2xl bg-gradient-to-br from-cyan-500/10 to-blue-600/10 border border-cyan-500/20 text-center">
                    <h2 className="text-2xl font-bold mb-3">Join the Mission</h2>
                    <p className="text-slate-400 mb-6">Cybertron is open source. Contributions, feedback, and stars are welcome.</p>
                    <a
                        href="https://github.com/cybertron-io"
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold transition-all duration-300 hover:scale-105"
                    >
                        Contribute on GitHub
                        <Zap className="w-4 h-4" />
                    </a>
                </div>
            </div>
        </div>
    );
}
