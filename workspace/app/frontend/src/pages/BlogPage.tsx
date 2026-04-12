import { useState } from 'react';
import { ArrowLeft, BookOpen, Calendar, Clock } from 'lucide-react';
import { Link } from 'react-router-dom';

const POSTS = [
  {
    title: 'Announcing Cybertron 1.0: Enterprise Cyber Operations Goes Open',
    excerpt:
      'Today we launch Cybertron - an enterprise cyber operations platform built for real security workflows, not demos.',
    date: '2026-02-26',
    readTime: '4 min',
    tag: 'Launch',
    tagColor: 'text-cyan-300 bg-cyan-500/10 border-cyan-500/20',
  },
  {
    title: 'How We Built Tenant-Aware RBAC Without a Third-Party Auth Provider',
    excerpt:
      'Deep dive into our JWT + HttpOnly cookie architecture with tenant isolation, role normalization, and token revocation.',
    date: '2026-02-20',
    readTime: '8 min',
    tag: 'Engineering',
    tagColor: 'text-purple-300 bg-purple-500/10 border-purple-500/20',
  },
  {
    title: 'Why We Reject Disposable Emails at Registration',
    excerpt:
      'Blocking temporary email domains is table stakes for B2B SaaS. Here is how we built a fail-closed blocklist.',
    date: '2026-02-15',
    readTime: '3 min',
    tag: 'Security',
    tagColor: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/20',
  },
  {
    title: 'The Case for Truthful Telemetry in Security Products',
    excerpt:
      'Fabricated demo data erodes trust. We made a deliberate choice: every metric in Cybertron is either real or clearly labeled.',
    date: '2026-02-10',
    readTime: '5 min',
    tag: 'Product',
    tagColor: 'text-amber-300 bg-amber-500/10 border-amber-500/20',
  },
];

export default function BlogPage() {
  const [email, setEmail] = useState('');

  const openPostBrief = (title: string) => {
    const subject = encodeURIComponent(`Cybertron Blog Briefing: ${title}`);
    const body = encodeURIComponent(
      `Please share the full briefing for:\n\n${title}\n\nMy email: ${email || 'not provided'}`
    );
    window.location.assign(`mailto:community@cybertron.io?subject=${subject}&body=${body}`);
  };

  const subscribe = () => {
    const normalized = email.trim();
    if (!normalized) {
      return;
    }
    const subject = encodeURIComponent('Cybertron Blog Subscription');
    const body = encodeURIComponent(
      `Please subscribe this email to Cybertron updates:\n\n${normalized}`
    );
    window.location.assign(`mailto:community@cybertron.io?subject=${subject}&body=${body}`);
  };

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
            <BookOpen className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-cyan-300 text-xs font-semibold tracking-widest uppercase">Blog</span>
          </div>
          <h1 className="text-4xl sm:text-5xl font-bold mb-4">
            Engineering and{' '}
            <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              Security Insights
            </span>
          </h1>
          <p className="text-lg text-slate-400 max-w-2xl">
            Technical deep-dives, product updates, and perspectives from the team building
            the next generation of cyber operations tooling.
          </p>
        </div>

        <div className="space-y-6">
          {POSTS.map(post => (
            <button
              key={post.title}
              type="button"
              onClick={() => openPostBrief(post.title)}
              title="Request the full briefing via email"
              className="group w-full text-left p-6 sm:p-8 rounded-2xl bg-white/[0.02] border border-white/[0.06] hover:border-cyan-500/20 hover:bg-white/[0.04] transition-all duration-300"
            >
              <div className="flex items-center gap-3 mb-3">
                <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${post.tagColor}`}>
                  {post.tag}
                </span>
                <span className="flex items-center gap-1 text-xs text-slate-500">
                  <Calendar className="w-3 h-3" />
                  {new Date(post.date).toLocaleDateString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    year: 'numeric',
                  })}
                </span>
                <span className="flex items-center gap-1 text-xs text-slate-500">
                  <Clock className="w-3 h-3" />
                  {post.readTime}
                </span>
              </div>
              <h2 className="text-xl font-bold text-white mb-2 group-hover:text-cyan-300 transition-colors">
                {post.title}
              </h2>
              <p className="text-sm text-slate-400 leading-relaxed">{post.excerpt}</p>
            </button>
          ))}
        </div>

        <div className="mt-12 p-8 rounded-2xl bg-gradient-to-br from-cyan-500/10 to-blue-600/10 border border-cyan-500/20 text-center">
          <h3 className="text-xl font-bold mb-2">Stay Updated</h3>
          <p className="text-slate-400 text-sm mb-4">Get security engineering insights delivered to your inbox.</p>
          <div className="flex items-center justify-center gap-3 max-w-md mx-auto">
            <input
              type="email"
              placeholder="you@company.com"
              value={email}
              onChange={event => setEmail(event.target.value)}
              className="flex-1 px-4 py-3 rounded-xl bg-white/[0.06] border border-white/[0.1] text-sm text-slate-300 outline-none focus:border-cyan-500/40 transition-colors"
            />
            <button
              type="button"
              onClick={subscribe}
              className="px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white text-sm font-semibold transition-all duration-300 hover:scale-105 whitespace-nowrap disabled:opacity-60 disabled:cursor-not-allowed"
              disabled={!email.trim()}
            >
              Subscribe
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
