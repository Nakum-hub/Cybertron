import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { BookOpenText, ExternalLink, Search } from 'lucide-react';
import { Link } from 'react-router-dom';
import { fetchOpenApiSpec } from '@/lib/backend';

type PathRecord = {
  path: string;
  methods: string[];
  group: string;
};

function toPathRecords(paths: Record<string, unknown>): PathRecord[] {
  return Object.entries(paths || {}).map(([path, methodsRaw]) => {
    const methods = Object.keys((methodsRaw || {}) as Record<string, unknown>)
      .map(method => method.toUpperCase())
      .sort();
    const segments = path.split('/').filter(Boolean);
    const group = segments[1] || segments[0] || 'core';
    return {
      path,
      methods,
      group,
    };
  });
}

export default function DocsPage() {
  const [search, setSearch] = useState('');
  const openApiQuery = useQuery({
    queryKey: ['openapi-docs'],
    queryFn: fetchOpenApiSpec,
    staleTime: 60_000,
  });

  const pathRecords = useMemo(
    () => toPathRecords(openApiQuery.data?.paths || {}),
    [openApiQuery.data?.paths]
  );

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) {
      return pathRecords;
    }

    return pathRecords.filter(record =>
      record.path.toLowerCase().includes(query) ||
      record.group.toLowerCase().includes(query) ||
      record.methods.some(method => method.toLowerCase().includes(query))
    );
  }, [pathRecords, search]);

  const grouped = useMemo(() => {
    const map = new Map<string, PathRecord[]>();
    for (const record of filtered) {
      const existing = map.get(record.group) || [];
      existing.push(record);
      map.set(record.group, existing);
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [filtered]);

  return (
    <div className="min-h-screen bg-[#07080D] text-white px-4 sm:px-6 py-8">
      <div className="max-w-6xl mx-auto space-y-6">
        <header className="rounded-2xl border border-white/10 bg-white/[0.03] p-5 sm:p-6">
          <p className="text-xs uppercase tracking-[0.2em] text-cyan-300 mb-2">Developer Docs</p>
          <h1 className="text-3xl font-bold mb-2">Cybertron API Documentation</h1>
          <p className="text-sm text-slate-300">
            Styled API index backed by live OpenAPI metadata. Use this as the primary docs surface instead of raw JSON.
          </p>
        </header>

        <section className="grid gap-4 sm:grid-cols-3">
          <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="text-xs text-slate-400 mb-1">Spec Version</p>
            <p className="text-lg font-semibold">{openApiQuery.data?.openapi || '--'}</p>
          </article>
          <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="text-xs text-slate-400 mb-1">API Version</p>
            <p className="text-lg font-semibold">{openApiQuery.data?.info?.version || '--'}</p>
          </article>
          <article className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
            <p className="text-xs text-slate-400 mb-1">Endpoints</p>
            <p className="text-lg font-semibold">{pathRecords.length}</p>
          </article>
        </section>

        <section className="rounded-xl border border-white/10 bg-white/[0.02] p-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-3">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <BookOpenText className="h-4 w-4 text-cyan-300" />
              Endpoint Catalog
            </h2>
            <a
              href="/api/v1/system/openapi"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-3 py-2 text-xs hover:bg-cyan-400/15"
            >
              Open Raw OpenAPI JSON
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
          </div>

          <label className="mb-3 flex items-center gap-2 rounded-lg border border-white/15 bg-white/[0.05] px-3 py-2">
            <Search className="h-4 w-4 text-slate-400" />
            <input
              value={search}
              onChange={event => setSearch(event.target.value)}
              placeholder="Search paths, method, or module..."
              className="w-full bg-transparent text-sm outline-none placeholder:text-slate-500"
            />
          </label>

          {openApiQuery.isLoading && <p className="text-sm text-slate-300">Loading API specification...</p>}
          {openApiQuery.isError && (
            <p className="text-sm text-red-300">
              Unable to load OpenAPI specification from backend.
            </p>
          )}

          <div className="space-y-4">
            {grouped.map(([group, records]) => (
              <div key={group} className="rounded-lg border border-white/10 bg-white/[0.02] p-3">
                <p className="text-xs uppercase tracking-[0.14em] text-cyan-200 mb-2">{group}</p>
                <div className="space-y-2">
                  {records
                    .sort((a, b) => a.path.localeCompare(b.path))
                    .map(record => (
                      <div key={record.path} className="rounded-md border border-white/10 bg-white/[0.02] p-2.5">
                        <p className="font-mono text-sm break-all">{record.path}</p>
                        <div className="mt-1 flex flex-wrap gap-1.5">
                          {record.methods.map(method => (
                            <span
                              key={`${record.path}:${method}`}
                              className="rounded-full border border-cyan-300/25 bg-cyan-400/10 px-2 py-0.5 text-[10px] font-semibold"
                            >
                              {method}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            ))}
          </div>
        </section>

        <div className="flex flex-wrap gap-3">
          <Link to="/status" className="inline-flex rounded-lg border border-white/20 bg-white/[0.04] px-4 py-2 text-sm hover:bg-white/[0.08]">
            System Status
          </Link>
          <Link to="/qa/ui-wiring" className="inline-flex rounded-lg border border-cyan-300/30 bg-cyan-400/10 px-4 py-2 text-sm hover:bg-cyan-400/15">
            UI Wiring QA
          </Link>
          <Link to="/qa/ui-checklist" className="inline-flex rounded-lg border border-white/20 bg-white/[0.04] px-4 py-2 text-sm hover:bg-white/[0.08]">
            UI Checklist
          </Link>
          <Link to="/" className="inline-flex rounded-lg border border-white/20 bg-white/[0.04] px-4 py-2 text-sm hover:bg-white/[0.08]">
            Back To Corporate Site
          </Link>
        </div>
      </div>
    </div>
  );
}
