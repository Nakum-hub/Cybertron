#!/usr/bin/env node

const fs = require('node:fs/promises');
const path = require('node:path');

const DEFAULT_OUTPUT = path.resolve(__dirname, 'data', 'cybertron_official_realworld_sft.jsonl');
const DEFAULT_MANIFEST = path.resolve(__dirname, 'data', 'cybertron_official_realworld_manifest.json');
const DEFAULT_CACHE_DIR = path.resolve(__dirname, 'cache', 'official-sources');
const DEFAULT_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const DEFAULT_ATTACK_URL =
  'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
const DEFAULT_OSCAL_URL =
  'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json';
const DEFAULT_NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

const CATEGORY_KEYWORDS = [
  {
    category: 'identity',
    keywords: ['active directory', 'entra', 'okta', 'identity', 'authentication', 'sso', 'ad fs'],
  },
  {
    category: 'network',
    keywords: ['fortios', 'vpn', 'firewall', 'router', 'gateway', 'pulse connect', 'citrix adc'],
  },
  {
    category: 'application-security',
    keywords: ['sharepoint', 'exchange', 'apache', 'tomcat', 'nginx', 'web', 'portal', 'confluence'],
  },
  {
    category: 'endpoint',
    keywords: ['chrome', 'edge', 'firefox', 'browser', 'windows', 'macos', 'ios', 'android'],
  },
  {
    category: 'virtualization',
    keywords: ['vmware', 'esxi', 'virtual', 'hyper-v', 'xen'],
  },
  {
    category: 'data-platform',
    keywords: ['sql', 'database', 'postgres', 'mysql', 'oracle', 'mongodb', 'redis'],
  },
];

const POLICY_BLUEPRINTS = [
  {
    suffix: 'baseline',
    organization: 'Cybertron Client',
    status: 'unassessed',
    titlePrefix: 'Baseline',
  },
  {
    suffix: 'startup',
    organization: 'Cybertron Startup',
    status: 'unassessed',
    titlePrefix: 'Startup',
  },
  {
    suffix: 'enterprise',
    organization: 'Cybertron Enterprise',
    status: 'unassessed',
    titlePrefix: 'Enterprise',
  },
];

function parseArgs(argv) {
  const args = {
    output: DEFAULT_OUTPUT,
    manifest: DEFAULT_MANIFEST,
    cacheDir: DEFAULT_CACHE_DIR,
    kevUrl: DEFAULT_KEV_URL,
    attackUrl: DEFAULT_ATTACK_URL,
    oscalUrl: DEFAULT_OSCAL_URL,
    nvdBaseUrl: DEFAULT_NVD_BASE_URL,
    kevLimit: 0,
    nvdDays: 120,
    nvdCriticalLimit: 1200,
    nvdHighLimit: 1500,
    riskWindow: 4,
    refresh: false,
    cacheTtlHours: 24,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const current = String(argv[index] || '');
    const next = argv[index + 1];
    if (current === '--out' && next) {
      args.output = path.resolve(next);
      index += 1;
      continue;
    }
    if (current === '--manifest' && next) {
      args.manifest = path.resolve(next);
      index += 1;
      continue;
    }
    if (current === '--cache-dir' && next) {
      args.cacheDir = path.resolve(next);
      index += 1;
      continue;
    }
    if (current === '--kev-limit' && next) {
      args.kevLimit = Number.parseInt(next, 10) || 0;
      index += 1;
      continue;
    }
    if (current === '--nvd-days' && next) {
      args.nvdDays = Math.max(7, Number.parseInt(next, 10) || args.nvdDays);
      index += 1;
      continue;
    }
    if (current === '--nvd-critical-limit' && next) {
      args.nvdCriticalLimit = Math.max(0, Number.parseInt(next, 10) || 0);
      index += 1;
      continue;
    }
    if (current === '--nvd-high-limit' && next) {
      args.nvdHighLimit = Math.max(0, Number.parseInt(next, 10) || 0);
      index += 1;
      continue;
    }
    if (current === '--risk-window' && next) {
      args.riskWindow = Math.max(2, Math.min(6, Number.parseInt(next, 10) || args.riskWindow));
      index += 1;
      continue;
    }
    if (current === '--cache-ttl-hours' && next) {
      args.cacheTtlHours = Math.max(1, Number.parseInt(next, 10) || args.cacheTtlHours);
      index += 1;
      continue;
    }
    if (current === '--refresh') {
      args.refresh = true;
    }
  }

  return args;
}

function slugify(value, fallback = 'item') {
  const normalized = String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return normalized || fallback;
}

function compactWhitespace(value) {
  return String(value || '')
    .replace(/\{\{[^}]+\}\}/g, '')
    .replace(/\[([^\]]+)\]\(#.+?\)/g, '$1')
    .replace(/\s+([:;,.])/g, '$1')
    .replace(/([:;])\./g, '.')
    .replace(/\(\s*\)/g, '')
    .replace(/\b(to|an|a|during|based on|of)\s*\./gi, '.')
    .replace(/\s+/g, ' ')
    .trim();
}

function cleanSentence(value, fallback = '') {
  const normalized = compactWhitespace(value);
  if (!normalized) {
    return fallback;
  }
  return normalized.endsWith('.') ? normalized : `${normalized}.`;
}

function uniqueStrings(items, limit = 0) {
  const seen = new Set();
  const output = [];
  for (const item of items) {
    const normalized = String(item || '').trim();
    if (!normalized || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    output.push(normalized);
    if (limit > 0 && output.length >= limit) {
      break;
    }
  }
  return output;
}

function buildChatText(messages) {
  return messages
    .map(message => {
      const role =
        message.role === 'system'
          ? 'System'
          : message.role === 'assistant'
            ? 'Assistant'
            : 'User';
      return `### ${role}\n${message.content}\n`;
    })
    .join('\n');
}

async function writeJsonl(filePath, rows) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const content = rows.map(row => JSON.stringify(row)).join('\n') + '\n';
  await fs.writeFile(filePath, content, 'utf8');
}

async function writeJson(filePath, payload) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
}

async function readJson(filePath) {
  const raw = await fs.readFile(filePath, 'utf8');
  return JSON.parse(raw);
}

async function fetchJsonCached({ cacheDir, cacheKey, url, refresh, cacheTtlHours }) {
  const cachePath = path.join(cacheDir, `${cacheKey}.json`);
  if (!refresh) {
    try {
      const stat = await fs.stat(cachePath);
      const ageMs = Date.now() - stat.mtimeMs;
      if (ageMs < cacheTtlHours * 60 * 60 * 1000) {
        return await readJson(cachePath);
      }
    } catch {}
  }

  const response = await fetch(url, {
    headers: {
      'User-Agent': 'Cybertron-Official-Corpus-Builder/1.0',
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch ${url}: ${response.status} ${response.statusText}`);
  }

  const payload = await response.json();
  await writeJson(cachePath, payload);
  return payload;
}

function buildNvdUrl(baseUrl, { severity, startDate, endDate, startIndex, resultsPerPage }) {
  const params = new URLSearchParams({
    pubStartDate: startDate,
    pubEndDate: endDate,
    cvssV3Severity: severity,
    startIndex: String(startIndex),
    resultsPerPage: String(resultsPerPage),
  });
  return `${baseUrl}?${params.toString()}`;
}

async function fetchRecentNvdVulnerabilities({
  cacheDir,
  refresh,
  cacheTtlHours,
  baseUrl,
  severity,
  days,
  limit,
}) {
  if (limit === 0) {
    return [];
  }

  const endDate = new Date().toISOString();
  const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  const cacheKey = `nvd-${severity.toLowerCase()}-${days}d-${limit || 'all'}`;
  const cachePath = path.join(cacheDir, `${cacheKey}.json`);

  if (!refresh) {
    try {
      const stat = await fs.stat(cachePath);
      const ageMs = Date.now() - stat.mtimeMs;
      if (ageMs < cacheTtlHours * 60 * 60 * 1000) {
        return await readJson(cachePath);
      }
    } catch {}
  }

  const perPage = Math.max(1, Math.min(limit || 2000, 2000));
  const firstUrl = buildNvdUrl(baseUrl, {
    severity,
    startDate,
    endDate,
    startIndex: 0,
    resultsPerPage: perPage,
  });
  const firstResponse = await fetch(firstUrl, {
    headers: {
      'User-Agent': 'Cybertron-Official-Corpus-Builder/1.0',
      Accept: 'application/json',
    },
  });

  if (!firstResponse.ok) {
    throw new Error(`Failed to fetch NVD ${severity} page 1: ${firstResponse.status} ${firstResponse.statusText}`);
  }

  const firstPayload = await firstResponse.json();
  const totalResults = Number(firstPayload.totalResults || 0);
  const targetCount = limit > 0 ? Math.min(limit, totalResults) : totalResults;
  const vulnerabilities = [...(firstPayload.vulnerabilities || [])];

  for (let startIndex = vulnerabilities.length; startIndex < targetCount; startIndex += perPage) {
    const pageUrl = buildNvdUrl(baseUrl, {
      severity,
      startDate,
      endDate,
      startIndex,
      resultsPerPage: Math.min(perPage, targetCount - startIndex),
    });
    const pageResponse = await fetch(pageUrl, {
      headers: {
        'User-Agent': 'Cybertron-Official-Corpus-Builder/1.0',
        Accept: 'application/json',
      },
    });
    if (!pageResponse.ok) {
      throw new Error(
        `Failed to fetch NVD ${severity} page starting at ${startIndex}: ${pageResponse.status} ${pageResponse.statusText}`
      );
    }
    const pagePayload = await pageResponse.json();
    vulnerabilities.push(...(pagePayload.vulnerabilities || []));
  }

  const trimmed = vulnerabilities.slice(0, targetCount);
  await writeJson(cachePath, trimmed);
  return trimmed;
}

function getEnglishDescription(descriptions) {
  const entry = (descriptions || []).find(item => String(item.lang || '').toLowerCase() === 'en');
  return compactWhitespace(entry?.value || '');
}

function parseCpeCriteria(criteria) {
  const parts = String(criteria || '').split(':');
  if (parts.length < 5) {
    return null;
  }
  const vendor = compactWhitespace(parts[3] || '');
  const product = compactWhitespace(parts[4] || '');
  if (!vendor || !product || product === '*') {
    return null;
  }
  return {
    vendor,
    product,
    slug: slugify(`${vendor}-${product}`),
    label: `${vendor.replace(/_/g, ' ')} ${product.replace(/_/g, ' ')}`,
  };
}

function collectAffectedProducts(configurations) {
  const results = [];

  function visitNodes(nodes) {
    for (const node of nodes || []) {
      for (const match of node.cpeMatch || []) {
        const parsed = parseCpeCriteria(match.criteria);
        if (parsed) {
          results.push(parsed);
        }
      }
      visitNodes(node.nodes || []);
    }
  }

  visitNodes(configurations || []);
  return uniqueStrings(results.map(item => JSON.stringify(item)))
    .map(item => JSON.parse(item))
    .slice(0, 8);
}

function getCvssInfo(metrics) {
  const buckets = [
    { key: 'cvssMetricV40', version: '4.0' },
    { key: 'cvssMetricV31', version: '3.1' },
    { key: 'cvssMetricV30', version: '3.0' },
    { key: 'cvssMetricV2', version: '2.0' },
  ];

  for (const bucket of buckets) {
    const entries = Array.isArray(metrics?.[bucket.key]) ? metrics[bucket.key] : [];
    for (const entry of entries) {
      const data = entry.cvssData || {};
      const baseScore = Number(data.baseScore);
      const severity =
        String(data.baseSeverity || entry.baseSeverity || '')
          .trim()
          .toUpperCase() || 'UNKNOWN';
      if (Number.isFinite(baseScore)) {
        return {
          score: baseScore,
          severity,
          vector: data.vectorString || '',
          version: bucket.version,
        };
      }
    }
  }

  return {
    score: null,
    severity: 'UNKNOWN',
    vector: '',
    version: '',
  };
}

function severityRank(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'critical') {
    return 4;
  }
  if (normalized === 'high') {
    return 3;
  }
  if (normalized === 'medium') {
    return 2;
  }
  if (normalized === 'low') {
    return 1;
  }
  return 0;
}

function severityToScore(severity, cvssScore) {
  if (Number.isFinite(cvssScore)) {
    return Math.max(30, Math.min(99, Math.round((cvssScore / 10) * 100)));
  }
  const normalized = String(severity || '').trim().toLowerCase();
  if (normalized === 'critical') {
    return 95;
  }
  if (normalized === 'high') {
    return 84;
  }
  if (normalized === 'medium') {
    return 62;
  }
  if (normalized === 'low') {
    return 35;
  }
  return 50;
}

function inferCategory(textParts) {
  const haystack = textParts
    .map(item => String(item || '').toLowerCase())
    .join(' ');
  for (const entry of CATEGORY_KEYWORDS) {
    if (entry.keywords.some(keyword => haystack.includes(keyword))) {
      return entry.category;
    }
  }
  return 'vulnerability';
}

function normalizeKevRecord(raw, nvdByCve) {
  const cveId = String(raw.cveID || '').trim().toUpperCase();
  const nvd = nvdByCve.get(cveId);
  const cvss = nvd?.cvss || {};
  const severity = cvss.severity && cvss.severity !== 'UNKNOWN'
    ? cvss.severity.toLowerCase()
    : String(raw.knownRansomwareCampaignUse || '').toLowerCase() === 'known'
      ? 'critical'
      : 'high';
  const description =
    nvd?.description ||
    cleanSentence(raw.shortDescription || raw.vulnerabilityName, 'Official description not available.');
  const affectedProducts = nvd?.affectedProducts?.length
    ? nvd.affectedProducts
    : [
        {
          vendor: raw.vendorProject || 'unknown-vendor',
          product: raw.product || 'unknown-product',
          slug: slugify(`${raw.vendorProject || 'vendor'}-${raw.product || 'product'}`),
          label: `${raw.vendorProject || 'Unknown vendor'} ${raw.product || 'Unknown product'}`,
        },
      ];
  const primaryProduct = affectedProducts[0];
  const category = inferCategory([
    raw.vendorProject,
    raw.product,
    raw.vulnerabilityName,
    description,
  ]);

  return {
    type: 'kev',
    cveId,
    vendorProject: cleanSentence(compactWhitespace(raw.vendorProject), '').replace(/\.$/, ''),
    product: cleanSentence(compactWhitespace(raw.product), '').replace(/\.$/, ''),
    vulnerabilityName: cleanSentence(raw.vulnerabilityName, 'Known exploited vulnerability.'),
    description,
    requiredAction: cleanSentence(raw.requiredAction, 'Apply the vendor remediation or compensating control.'),
    dueDate: String(raw.dueDate || '').trim(),
    knownRansomwareCampaignUse: String(raw.knownRansomwareCampaignUse || '').trim() || 'Unknown',
    notes: cleanSentence(raw.notes, ''),
    cwes: uniqueStrings((raw.cwes || []).map(item => cleanSentence(item, '').replace(/\.$/, '')), 6),
    severity,
    cvssScore: cvss.score,
    publishedAt: nvd?.publishedAt || '',
    lastModifiedAt: nvd?.lastModifiedAt || '',
    affectedProducts,
    primaryProduct,
    category,
  };
}

function normalizeNvdRecord(wrapper) {
  const cve = wrapper?.cve || {};
  const cvss = getCvssInfo(cve.metrics);
  const affectedProducts = collectAffectedProducts(cve.configurations);
  const description = cleanSentence(
    getEnglishDescription(cve.descriptions),
    'Official description not available.'
  );
  const primaryProduct = affectedProducts[0] || {
    vendor: 'unknown-vendor',
    product: 'unknown-product',
    slug: slugify(cve.id, 'unknown-product'),
    label: 'Unknown product',
  };
  const severity = String(cvss.severity || 'UNKNOWN').toLowerCase();

  return {
    type: 'nvd',
    cveId: String(cve.id || '').trim().toUpperCase(),
    description,
    cvss,
    severity,
    publishedAt: String(cve.published || '').trim(),
    lastModifiedAt: String(cve.lastModified || '').trim(),
    weaknesses: uniqueStrings(
      (cve.weaknesses || [])
        .flatMap(item => item.description || [])
        .map(item => cleanSentence(item.value, '').replace(/\.$/, '')),
      8
    ),
    affectedProducts,
    primaryProduct,
    references: uniqueStrings((cve.references || []).map(item => item.url), 6),
    category: inferCategory([
      primaryProduct.label,
      description,
      ...(affectedProducts || []).map(item => item.label),
    ]),
  };
}

function buildThreatPrompt(payload) {
  const publishedAt = payload.publishedAt || 'unknown';
  const lastModifiedAt = payload.lastModifiedAt || 'unknown';
  return [
    `Tenant: ${payload.tenant}`,
    `CVE: ${payload.cveId}`,
    `Severity: ${payload.severity}`,
    `CVSS: ${payload.cvssScore ?? 'n/a'}`,
    `Published: ${publishedAt}`,
    `Last modified: ${lastModifiedAt}`,
    'Summarize this vulnerability in plain English.',
    'Return plain text only using these exact headings:',
    'What it means',
    'Business impact',
    'Immediate mitigation steps',
    'What to monitor after mitigation',
    'Evidence basis',
    'Reference the exact CVE ID and real severity from the input data.',
    'Do not invent vendor names, affected products, indicators, or remediation that is not supported by the input.',
    '',
    payload.description,
  ].join('\n');
}

function buildThreatResponse(payload) {
  const productLabel = payload.primaryProduct?.label || 'the affected product';
  const evidenceLines = [
    `- CVE ID: ${payload.cveId}`,
    `- Severity: ${String(payload.severity || 'unknown').toUpperCase()}`,
  ];
  if (Number.isFinite(payload.cvssScore)) {
    evidenceLines.push(`- CVSS: ${payload.cvssScore.toFixed(1)}`);
  }
  if (payload.vendorProject) {
    evidenceLines.push(`- Vendor: ${payload.vendorProject}`);
  }
  if (payload.product) {
    evidenceLines.push(`- Product: ${payload.product}`);
  }
  if (payload.vulnerabilityName) {
    evidenceLines.push(`- Vulnerability name: ${payload.vulnerabilityName}`);
  }
  if (payload.knownRansomwareCampaignUse) {
    evidenceLines.push(`- Known ransomware campaign use: ${payload.knownRansomwareCampaignUse}`);
  }
  if (payload.dueDate) {
    evidenceLines.push(`- CISA remediation due date: ${payload.dueDate}`);
  }
  for (const cwe of payload.cwes || payload.weaknesses || []) {
    evidenceLines.push(`- Weakness: ${cwe}`);
  }
  evidenceLines.push(`- Primary affected product: ${productLabel}`);

  const mitigations = [];
  if (payload.requiredAction) {
    mitigations.push(`- ${payload.requiredAction}`);
  }
  mitigations.push(`- Validate whether ${productLabel} is exposed in your environment and prioritize vendor-approved remediation.`);
  mitigations.push(`- Restrict administrative or internet-facing access to ${productLabel} until remediation is verified.`);
  mitigations.push(`- Confirm patch or workaround coverage across every instance of ${productLabel}.`);

  const monitoring = [
    `- Hunt for repeated exploitation attempts against ${payload.cveId} in edge, proxy, EDR, and authentication telemetry.`,
    `- Watch ${productLabel} for service restarts, abnormal child processes, or unauthorized configuration changes after remediation.`,
    '- Track follow-up vendor guidance, rollback notices, or revised indicators from authoritative advisories.',
    '- Verify that exposure scanning and asset inventory no longer show the vulnerable version.',
  ];

  const businessImpact =
    payload.type === 'kev'
      ? `${payload.cveId} is in CISA's Known Exploited Vulnerabilities catalog, which means exploitation has already been observed in the wild. If ${productLabel} is deployed, treat this as active operational risk with potential for rapid compromise, service disruption, credential theft, or follow-on ransomware activity depending on how the product is exposed.`
      : `${payload.cveId} is a ${String(payload.severity || 'unknown').toUpperCase()} severity vulnerability. If ${productLabel} is deployed in a reachable or privileged path, it can increase the likelihood of service compromise, data exposure, and operational disruption until vendor remediation is complete.`;

  return [
    'What it means',
    `${payload.cveId} affects ${productLabel}. ${payload.description}`,
    '',
    'Business impact',
    businessImpact,
    '',
    'Immediate mitigation steps',
    ...mitigations,
    '',
    'What to monitor after mitigation',
    ...monitoring,
    '',
    'Evidence basis',
    ...evidenceLines,
  ].join('\n');
}

function buildThreatRow({ id, source, payload, sourceLinks }) {
  const systemPrompt =
    'You are Cybertron Threat Intel Summarizer. Write concise executive and analyst-friendly vulnerability summaries.';
  const userPrompt = buildThreatPrompt(payload);
  const assistantContent = buildThreatResponse(payload);
  const messages = [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: userPrompt },
    { role: 'assistant', content: assistantContent },
  ];

  return {
    id,
    taskType: 'threat_summary',
    source,
    aiGenerated: false,
    sourceLinks,
    payload,
    response: {
      summaryText: assistantContent,
      confidence: payload.type === 'kev' ? 'high' : 'medium',
      confidenceNote:
        payload.type === 'kev'
          ? 'Grounded in official CISA KEV and NVD data.'
          : 'Grounded in official NVD data and should still be checked against vendor advisories before operational action.',
    },
    messages,
    text: buildChatText(messages),
  };
}

function buildRiskPrompt(payload) {
  return [
    `Tenant: ${payload.tenant}`,
    '',
    'Analyze the cybersecurity risk portfolio and findings below.',
    'Respond ONLY with valid JSON using this exact schema (no markdown wrapping):',
    '',
    '{',
    '  "explanation": "<executive summary>",',
    '  "mitigations": ["<action 1>", "<action 2>", ...],',
    '  "evidence": ["<asset-id-or-finding-id>", "<severity-or-category>", ...]',
    '}',
    '',
    'Rules for "explanation":',
    '- Write for a non-technical executive audience.',
    '- Summarize overall risk posture with key patterns, business impact, and exposure.',
    '- Use concise bullet-point format (use \\n for line breaks).',
    '- Reference at least one exact asset ID from the findings when available.',
    '- End with 3-5 concrete next actions leadership should authorize immediately.',
    '',
    'Rules for "mitigations":',
    '- Provide 5-10 specific, actionable remediation steps ordered by urgency.',
    '- Reference actual asset IDs, categories, and severity levels from the findings.',
    '- Specify exact technologies, configurations, or procedures to apply.',
    '- Each item must be one concrete sentence an engineer can act on today.',
    '- Prioritize critical and high severity findings first.',
    '',
    'Rules for "evidence":',
    '- List the exact asset IDs, finding IDs, severities, or categories that support the explanation.',
    '- Do not invent evidence that is not present in the input data.',
    '',
    'Portfolio and findings data:',
    JSON.stringify(
      {
        portfolio: payload.portfolio,
        findings: payload.findings,
      },
      null,
      2
    ),
  ].join('\n');
}

function buildRiskResponse(payload) {
  const sortedFindings = [...payload.findings].sort((left, right) => Number(right.score || 0) - Number(left.score || 0));
  const criticalCount = sortedFindings.filter(item => item.severity === 'critical').length;
  const highCount = sortedFindings.filter(item => item.severity === 'high').length;
  const categories = uniqueStrings(sortedFindings.map(item => item.category), 5);
  const prioritizedAssets = uniqueStrings(sortedFindings.map(item => item.assetId), 5);
  const topCves = uniqueStrings(sortedFindings.map(item => item.id), 6);

  const explanationLines = [
    `- Overall posture: Elevated concentration risk across ${payload.portfolio.totalAssets} technology asset(s), driven by ${sortedFindings.length} officially sourced finding(s) with ${criticalCount} critical and ${highCount} high severity exposure(s).`,
    `- Exposure pattern: ${prioritizedAssets.join(', ')} carry the most urgent remediation pressure, with findings mapped to ${categories.join(', ')} risk categories.`,
    `- Business impact: These findings are tied to real-world exploited or recently published vulnerabilities, so delayed remediation increases the chance of service disruption, privilege misuse, data exposure, or rapid attacker foothold expansion.`,
    `- Highest-priority evidence: ${topCves.join(', ')}.`,
    '- Leadership actions to authorize immediately:',
    `- Approve emergency remediation windows for ${prioritizedAssets.slice(0, 3).join(', ')} before routine change backlog work.`,
    '- Require internet-exposed management surfaces to be restricted or isolated until every listed fix is validated.',
    '- Fund rapid threat hunting and telemetry review for signs of exploitation tied to the listed CVEs and affected technologies.',
    '- Hold technology owners to a patch-verification checkpoint with evidence of version closure and rollback readiness.',
  ];

  const mitigations = uniqueStrings(
    sortedFindings.flatMap(item => {
      const suggestions = [
        item.details?.mitigationSuggestions?.[0],
        item.details?.mitigationSuggestions?.[1],
        `Validate that ${item.assetId} is no longer reachable through unnecessary administrative, VPN, or public exposure paths after remediation.`,
        `Search SIEM and EDR telemetry for exploitation attempts targeting ${item.id} on ${item.assetId}, then preserve evidence for any hit before cleanup.`,
      ];
      return suggestions.filter(Boolean);
    }),
    10
  );

  const evidence = uniqueStrings(
    sortedFindings.flatMap(item => [item.id, item.assetId, item.severity, item.category]),
    12
  );

  return {
    explanation: explanationLines.join('\n'),
    mitigations,
    evidence,
  };
}

function buildRiskRow({ id, source, payload, sourceLinks }) {
  const systemPrompt =
    'You are Cybertron Risk Copilot, an expert cybersecurity risk analyst. You produce structured JSON containing executive risk briefings and prioritized, finding-specific mitigation plans. Always respond with valid JSON only.';
  const userPrompt = buildRiskPrompt(payload);
  const response = buildRiskResponse(payload);
  const assistantContent = JSON.stringify(response, null, 2);
  const messages = [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: userPrompt },
    { role: 'assistant', content: assistantContent },
  ];

  return {
    id,
    taskType: 'risk_explanation',
    source,
    aiGenerated: false,
    sourceLinks,
    payload,
    response,
    messages,
    text: buildChatText(messages),
  };
}

function collectProse(parts, output) {
  for (const part of parts || []) {
    const prose = compactWhitespace(part.prose);
    if (prose) {
      output.push(prose);
    }
    collectProse(part.parts || [], output);
  }
}

function collectStatementProse(parts, output, inStatement = false) {
  for (const part of parts || []) {
    const name = String(part.name || '').trim().toLowerCase();
    const nextInStatement = inStatement || name === 'statement' || name === 'item';
    if (nextInStatement) {
      const prose = compactWhitespace(part.prose);
      if (prose) {
        output.push(prose);
      }
    }
    collectStatementProse(part.parts || [], output, nextInStatement);
  }
}

function extractControlSummary(control) {
  const proseLines = [];
  collectStatementProse(control.parts || [], proseLines);
  const cleanedStatements = uniqueStrings(
    proseLines
      .map(item => cleanSentence(item))
      .filter(item => item.split(/\s+/).length >= 4)
      .filter(item => !/[=:;]\.$/.test(item))
      .filter(item => !/\b(to|an|a|during|based on)\.$/i.test(item)),
    6
  );
  return {
    controlId: String(control.id || '').trim().toLowerCase(),
    title: cleanSentence(control.title, 'Control'),
    statements: cleanedStatements.length > 0 ? cleanedStatements : [cleanSentence(control.title, 'Control requirement.')],
  };
}

function inferPolicyKey(groupId, groupTitle) {
  const normalized = String(groupId || '').trim().toLowerCase();
  if (normalized === 'ac' || normalized === 'ia') {
    return 'access-control-policy';
  }
  if (normalized === 'ir') {
    return 'incident-response-policy';
  }
  if (normalized === 'au') {
    return 'logging-monitoring-policy';
  }
  if (normalized === 'sc' || normalized === 'mp' || normalized === 'pt') {
    return 'data-protection-policy';
  }
  if (normalized === 'sr') {
    return 'third-party-risk-policy';
  }
  if (normalized === 'cm' || normalized === 'si' || normalized === 'ra') {
    return 'vulnerability-management-policy';
  }
  if (normalized === 'cp') {
    return 'business-continuity-policy';
  }
  return `${slugify(groupTitle, normalized)}-policy`;
}

function buildPolicyPrompt(payload) {
  return [
    `Tenant: ${payload.tenant}`,
    `Organization: ${payload.organization}`,
    `Policy key: ${payload.policyKey}`,
    'Generate an actionable policy document using these exact sections and headings:',
    'Purpose, Scope, Control Statements, Monitoring, Exceptions, Review Cadence, and Mapped Controls.',
    'Reference the exact mapped control IDs and current statuses from the input JSON.',
    'Do not cite regulations or standards that are not present in the input JSON.',
    'Return plain text only.',
    'Context JSON:',
    JSON.stringify(
      {
        controls: payload.controls,
      },
      null,
      2
    ),
  ].join('\n');
}

function selectBestPolicyStatement(control) {
  const candidates = (control.statementHighlights || [])
    .map(item => cleanSentence(item))
    .filter(item => item.split(/\s+/).length >= 6)
    .filter(item => !/\b(an|a|to|when|during|following)\b[^.]*\.$/i.test(item))
    .filter(item => !/^(policy and|group and role membership|identify and document)\b/i.test(item));
  return candidates[0] || '';
}

function buildPolicyControlStatement(control) {
  const label = `${String(control.controlId || '').toUpperCase()} ${control.title}`;
  const bestStatement = selectBestPolicyStatement(control);
  if (bestStatement) {
    return `${label}: ${bestStatement}`;
  }
  return `${label}: Maintain documented ownership, operating procedures, evidence collection, and review cadence for this control area.`;
}

function buildPolicyDocument(payload) {
  const statements = uniqueStrings(payload.controls.map(buildPolicyControlStatement), 8);
  const monitoring = uniqueStrings(
    payload.controls.map(
      control =>
        `Monitor evidence, review cadence, and exceptions for ${String(control.controlId || '').toUpperCase()} ${control.title}.`
    ),
    6
  );
  const controlAppendix = payload.controls
    .map(
      control =>
        `- ${control.controlId}: ${control.status}${control.notes ? ` | ${control.notes}` : ''}`
    )
    .join('\n');

  return [
    `# ${payload.documentTitle}`,
    '',
    '## Purpose',
    `Establish a practical ${payload.policyKey.replace(/-/g, ' ')} baseline for ${payload.organization} using the mapped control obligations supplied in the request.`,
    '',
    '## Scope',
    `Applies to the systems, teams, services, vendors, and operational workflows that inherit the mapped control set for ${payload.organization}.`,
    '',
    '## Control Statements',
    ...statements.map(item => `- ${item}`),
    '',
    '## Monitoring',
    ...monitoring.map(item => `- ${item}`),
    '',
    '## Exceptions',
    '- Exceptions require documented business justification, risk acceptance, named compensating controls, and an expiration date owned by an accountable leader.',
    '- Any exception touching privileged access, internet exposure, or regulated data must be re-approved before renewal.',
    '',
    '## Review Cadence',
    '- Review this draft at least annually and after material incidents, audits, architectural changes, or control failures.',
    '- Track evidence updates whenever a mapped control changes status from unassessed to implemented or partially implemented.',
    '',
    '## Mapped Controls',
    controlAppendix,
  ].join('\n');
}

function buildPolicyRow({ id, source, payload, sourceLinks }) {
  const systemPrompt =
    'You are a SOC2 compliance writer. Produce practical, audit-ready policy language for startup security operations.';
  const userPrompt = buildPolicyPrompt(payload);
  const assistantContent = buildPolicyDocument(payload);
  const messages = [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: userPrompt },
    { role: 'assistant', content: assistantContent },
  ];

  return {
    id,
    taskType: 'policy_draft',
    source,
    aiGenerated: false,
    sourceLinks,
    payload,
    response: {
      policyKey: payload.policyKey,
      content: assistantContent,
      approvalStatus: 'draft',
      requiresApproval: true,
      approvalNote: 'Draft built from official control baselines and still requires organization-specific review before enforcement.',
    },
    messages,
    text: buildChatText(messages),
  };
}

function buildThreatRows({ kevRecords, nvdCriticalRecords, nvdHighRecords }) {
  const rows = [];
  const coveredCves = new Set();

  for (const record of kevRecords) {
    coveredCves.add(record.cveId);
    const payload = {
      tenant: 'global',
      type: 'kev',
      cveId: record.cveId,
      severity: record.severity,
      cvssScore: record.cvssScore,
      description: record.description,
      publishedAt: record.publishedAt || '',
      lastModifiedAt: record.lastModifiedAt || '',
      vendorProject: record.vendorProject,
      product: record.product,
      vulnerabilityName: record.vulnerabilityName,
      requiredAction: record.requiredAction,
      dueDate: record.dueDate,
      knownRansomwareCampaignUse: record.knownRansomwareCampaignUse,
      cwes: record.cwes,
      primaryProduct: record.primaryProduct,
    };
    rows.push(
      buildThreatRow({
        id: `official-threat-kev-${slugify(record.cveId, 'cve')}`,
        source: 'official-cisa-kev+nvd',
        payload,
        sourceLinks: [DEFAULT_KEV_URL, DEFAULT_NVD_BASE_URL],
      })
    );
  }

  for (const record of [...nvdCriticalRecords, ...nvdHighRecords]) {
    if (!record.cveId || coveredCves.has(record.cveId)) {
      continue;
    }
    coveredCves.add(record.cveId);
    const payload = {
      tenant: 'global',
      type: 'nvd',
      cveId: record.cveId,
      severity: record.severity,
      cvssScore: record.cvss.score,
      description: record.description,
      publishedAt: record.publishedAt,
      lastModifiedAt: record.lastModifiedAt,
      primaryProduct: record.primaryProduct,
      weaknesses: record.weaknesses,
    };
    rows.push(
      buildThreatRow({
        id: `official-threat-nvd-${slugify(record.cveId, 'cve')}`,
        source: 'official-nvd',
        payload,
        sourceLinks: [DEFAULT_NVD_BASE_URL],
      })
    );
  }

  return rows;
}

function buildRiskFindings(records) {
  return records.map(record => ({
    id: record.cveId,
    category: record.category,
    severity: record.severity,
    score: severityToScore(record.severity, record.cvssScore),
    assetId: record.primaryProduct?.slug || slugify(`${record.vendorProject}-${record.product}`, 'technology'),
    details: {
      title: record.vulnerabilityName || record.description,
      source: record.type === 'kev' ? 'cisa-kev' : 'nvd',
      mitigationSuggestions: uniqueStrings(
        [
          record.requiredAction,
          `Apply the vendor-approved remediation for ${record.primaryProduct?.label || record.product || record.cveId} and verify the vulnerable version is no longer present.`,
          `Reduce public or administrative exposure to ${record.primaryProduct?.label || record.product || record.cveId} until patch validation is complete.`,
        ],
        3
      ),
    },
  }));
}

function buildRiskRows(kevRecords, riskWindow) {
  const vendorGroups = new Map();
  const productGroups = new Map();

  for (const record of kevRecords) {
    const vendorKey = slugify(record.vendorProject || record.primaryProduct?.vendor || 'vendor', 'vendor');
    const productKey = record.primaryProduct?.slug || slugify(record.product || record.cveId, 'product');

    const vendorEntries = vendorGroups.get(vendorKey) || [];
    vendorEntries.push(record);
    vendorGroups.set(vendorKey, vendorEntries);

    const productEntries = productGroups.get(productKey) || [];
    productEntries.push(record);
    productGroups.set(productKey, productEntries);
  }

  const rows = [];
  const seenIds = new Set();

  function addScenario(prefix, groupingKey, records) {
    if (records.length < 2) {
      return;
    }
    const sorted = [...records].sort((left, right) => {
      const severityDelta = severityRank(right.severity) - severityRank(left.severity);
      if (severityDelta !== 0) {
        return severityDelta;
      }
      return Number(right.cvssScore || 0) - Number(left.cvssScore || 0);
    });
    const step = Math.max(2, riskWindow - 1);
    for (let index = 0; index < sorted.length; index += step) {
      const window = sorted.slice(index, index + riskWindow);
      if (window.length < 2) {
        continue;
      }
      const scenarioId = `${prefix}-${groupingKey}-${String(index + 1).padStart(3, '0')}`;
      if (seenIds.has(scenarioId)) {
        continue;
      }
      seenIds.add(scenarioId);
      const findings = buildRiskFindings(window);
      const payload = {
        tenant: 'global',
        portfolio: {
          totalAssets: uniqueStrings(findings.map(item => item.assetId)).length,
          criticalAssets: findings.filter(item => item.severity === 'critical').length,
          internetFacingAssets: findings.length,
        },
        findings,
      };
      rows.push(
        buildRiskRow({
          id: `official-risk-${scenarioId}`,
          source: 'official-cisa-kev-scenario',
          payload,
          sourceLinks: [DEFAULT_KEV_URL, DEFAULT_NVD_BASE_URL],
        })
      );
    }
  }

  for (const [vendorKey, records] of vendorGroups.entries()) {
    addScenario('vendor', vendorKey, records);
  }
  for (const [productKey, records] of productGroups.entries()) {
    addScenario('product', productKey, records);
  }

  return rows;
}

function buildPolicyRows(oscalPayload) {
  const rows = [];
  const groups = Array.isArray(oscalPayload?.catalog?.groups) ? oscalPayload.catalog.groups : [];

  for (const group of groups) {
    const groupId = String(group.id || '').trim().toLowerCase();
    const groupTitle = cleanSentence(group.title, 'Security Control Family.').replace(/\.$/, '');
    const controls = (group.controls || []).map(extractControlSummary).filter(control => control.controlId);
    if (controls.length === 0) {
      continue;
    }

    const policyKey = inferPolicyKey(groupId, groupTitle);
    for (const blueprint of POLICY_BLUEPRINTS) {
      const subset = controls.slice(0, Math.min(8, controls.length)).map(control => ({
        controlId: control.controlId,
        status: blueprint.status,
        notes: `${groupTitle} baseline derived from official control text.`,
        title: control.title.replace(/\.$/, ''),
        statementHighlights: control.statements,
      }));
      const payload = {
        tenant: 'global',
        organization: blueprint.organization,
        policyKey,
        documentTitle: `${blueprint.titlePrefix} ${groupTitle} Policy`,
        controls: subset,
      };
      rows.push(
        buildPolicyRow({
          id: `official-policy-${groupId}-${blueprint.suffix}`,
          source: 'official-nist-oscal',
          payload,
          sourceLinks: [DEFAULT_OSCAL_URL],
        })
      );
    }
  }

  return rows;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const startedAt = new Date().toISOString();
  await fs.mkdir(args.cacheDir, { recursive: true });

  const attackPayload = await fetchJsonCached({
    cacheDir: args.cacheDir,
    cacheKey: 'mitre-enterprise-attack',
    url: args.attackUrl,
    refresh: args.refresh,
    cacheTtlHours: args.cacheTtlHours,
  });
  const kevPayload = await fetchJsonCached({
    cacheDir: args.cacheDir,
    cacheKey: 'cisa-kev',
    url: args.kevUrl,
    refresh: args.refresh,
    cacheTtlHours: args.cacheTtlHours,
  });
  const oscalPayload = await fetchJsonCached({
    cacheDir: args.cacheDir,
    cacheKey: 'nist-oscal-800-53-rev5',
    url: args.oscalUrl,
    refresh: args.refresh,
    cacheTtlHours: args.cacheTtlHours,
  });

  const nvdCriticalWrappers = await fetchRecentNvdVulnerabilities({
    cacheDir: args.cacheDir,
    refresh: args.refresh,
    cacheTtlHours: args.cacheTtlHours,
    baseUrl: args.nvdBaseUrl,
    severity: 'CRITICAL',
    days: args.nvdDays,
    limit: args.nvdCriticalLimit,
  });
  const nvdHighWrappers = await fetchRecentNvdVulnerabilities({
    cacheDir: args.cacheDir,
    refresh: args.refresh,
    cacheTtlHours: args.cacheTtlHours,
    baseUrl: args.nvdBaseUrl,
    severity: 'HIGH',
    days: args.nvdDays,
    limit: args.nvdHighLimit,
  });

  const nvdCriticalRecords = nvdCriticalWrappers.map(normalizeNvdRecord);
  const nvdHighRecords = nvdHighWrappers.map(normalizeNvdRecord);
  const nvdByCve = new Map(
    [...nvdCriticalRecords, ...nvdHighRecords].map(record => [record.cveId, record])
  );

  const kevVulnerabilities = Array.isArray(kevPayload?.vulnerabilities)
    ? kevPayload.vulnerabilities
    : [];
  const kevRecords = kevVulnerabilities
    .slice(0, args.kevLimit > 0 ? args.kevLimit : kevVulnerabilities.length)
    .map(item => normalizeKevRecord(item, nvdByCve));

  const threatRows = buildThreatRows({
    kevRecords,
    nvdCriticalRecords,
    nvdHighRecords,
  });
  const riskRows = buildRiskRows(kevRecords, args.riskWindow);
  const policyRows = buildPolicyRows(oscalPayload);
  const rows = [...threatRows, ...riskRows, ...policyRows];

  await writeJsonl(args.output, rows);

  const manifest = {
    ok: true,
    startedAt,
    finishedAt: new Date().toISOString(),
    output: args.output,
    taskCounts: {
      threat_summary: threatRows.length,
      risk_explanation: riskRows.length,
      policy_draft: policyRows.length,
    },
    sourceCounts: {
      kevCatalogEntries: kevRecords.length,
      nvdCriticalEntries: nvdCriticalRecords.length,
      nvdHighEntries: nvdHighRecords.length,
      mitreAttackObjects: Array.isArray(attackPayload?.objects) ? attackPayload.objects.length : 0,
      oscalFamilies: Array.isArray(oscalPayload?.catalog?.groups) ? oscalPayload.catalog.groups.length : 0,
    },
    cacheDir: args.cacheDir,
    sources: {
      kev: args.kevUrl,
      nvd: args.nvdBaseUrl,
      mitreAttack: args.attackUrl,
      nistOscal: args.oscalUrl,
    },
  };

  await writeJson(args.manifest, manifest);
  process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
}

main().catch(error => {
  console.error(
    JSON.stringify(
      {
        ok: false,
        message: error.message,
      },
      null,
      2
    )
  );
  process.exitCode = 1;
});
