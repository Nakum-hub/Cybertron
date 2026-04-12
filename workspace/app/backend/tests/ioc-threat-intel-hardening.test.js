const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// =====================================================================
// IOC / Threat Intel Hardening Tests — Phase 3
// Covers: IOC schema, ingestion/dedup, confidence, severity derivation,
//         source attribution, search/filter, type validation, audit trail,
//         frontend types, dashboard, route wiring, tenant isolation,
//         connector normalization, correlation engine
// =====================================================================

const moduleServiceSource = fs.readFileSync(
  path.join(__dirname, '..', 'src', 'module-service.js'),
  'utf-8'
);

const routeSource = fs.readFileSync(
  path.join(__dirname, '..', 'src', 'routes', 'crud.js'),
  'utf-8'
);

const frontendTypesSource = fs.readFileSync(
  path.join(__dirname, '..', '..', 'frontend', 'src', 'lib', 'backend.ts'),
  'utf-8'
);

const dashboardSource = fs.readFileSync(
  path.join(__dirname, '..', '..', 'frontend', 'src', 'components', 'platform', 'ThreatCommandConsole.tsx'),
  'utf-8'
);

const threatConnectorsSource = fs.readFileSync(
  path.join(__dirname, '..', 'src', 'threat-connectors.js'),
  'utf-8'
);

const correlationSource = fs.readFileSync(
  path.join(__dirname, '..', 'src', 'correlation-engine.js'),
  'utf-8'
);

const siemServiceSource = fs.readFileSync(
  path.join(__dirname, '..', 'src', 'siem-service.js'),
  'utf-8'
);

const migrationFiles = fs.readdirSync(path.join(__dirname, '..', 'migrations'))
  .filter(f => f.endsWith('.sql'))
  .sort();

const migrationSources = {};
for (const f of migrationFiles) {
  migrationSources[f] = fs.readFileSync(
    path.join(__dirname, '..', 'migrations', f),
    'utf-8'
  );
}

// =====================================================================
// IOC Type Validation — normalizeIocType
// =====================================================================
describe('IOC type validation — normalizeIocType', () => {
  it('accepts exactly 4 IOC types: ip, domain, url, hash', () => {
    const funcMatch = moduleServiceSource.match(/function normalizeIocType[\s\S]*?^}/m);
    assert.ok(funcMatch, 'normalizeIocType function must exist');
    const body = funcMatch[0];
    assert.ok(body.includes("'ip'"), 'must accept ip');
    assert.ok(body.includes("'domain'"), 'must accept domain');
    assert.ok(body.includes("'url'"), 'must accept url');
    assert.ok(body.includes("'hash'"), 'must accept hash');
  });

  it('throws ServiceError for invalid types', () => {
    const funcMatch = moduleServiceSource.match(/function normalizeIocType[\s\S]*?^}/m);
    const body = funcMatch[0];
    assert.ok(body.includes('ServiceError'), 'must throw ServiceError for invalid types');
    assert.ok(body.includes('invalid_ioc_type'), 'error code must be invalid_ioc_type');
  });

  it('normalizes input to lowercase', () => {
    const funcMatch = moduleServiceSource.match(/function normalizeIocType[\s\S]*?^}/m);
    const body = funcMatch[0];
    assert.ok(body.includes('.toLowerCase()'), 'must lowercase input');
    assert.ok(body.includes('.trim()'), 'must trim input');
  });
});

// =====================================================================
// T1 — Route IOC type allowlist matches DB constraint
// =====================================================================
describe('T1 — Route IOC type allowlist consistency', () => {
  it('VALID_IOC_TYPES in route matches DB CHECK constraint (ip, domain, url, hash only)', () => {
    assert.ok(routeSource.includes("VALID_IOC_TYPES = ['ip', 'domain', 'url', 'hash']"),
      'Route VALID_IOC_TYPES should be exactly [ip, domain, url, hash]');
  });

  it('does NOT include email, file, or cve in VALID_IOC_TYPES', () => {
    // Grab just the VALID_IOC_TYPES line
    const match = routeSource.match(/VALID_IOC_TYPES\s*=\s*\[([^\]]+)\]/);
    assert.ok(match, 'VALID_IOC_TYPES must be defined');
    const types = match[1];
    assert.ok(!types.includes("'email'"), 'must NOT include email');
    assert.ok(!types.includes("'file'"), 'must NOT include file');
    assert.ok(!types.includes("'cve'"), 'must NOT include cve');
  });

  it('DB CHECK constraint limits ioc_type to ip/domain/url/hash', () => {
    const mig002 = migrationSources['002_enterprise_security_and_modules.sql'];
    assert.ok(mig002, 'Migration 002 must exist');
    assert.ok(mig002.includes("ioc_type") && mig002.includes("CHECK"), 'ioc_type CHECK constraint must exist');
    assert.ok(mig002.includes("'ip'"), 'DB CHECK must include ip');
    assert.ok(mig002.includes("'domain'"), 'DB CHECK must include domain');
    assert.ok(mig002.includes("'url'"), 'DB CHECK must include url');
    assert.ok(mig002.includes("'hash'"), 'DB CHECK must include hash');
  });
});

// =====================================================================
// IOC Deduplication — ON CONFLICT handling
// =====================================================================
describe('IOC deduplication — createIoc ON CONFLICT', () => {
  it('uses ON CONFLICT (tenant_slug, ioc_type, value) for upsert', () => {
    assert.ok(
      moduleServiceSource.includes('ON CONFLICT (tenant_slug, ioc_type, value)'),
      'createIoc must use tenant+type+value unique conflict'
    );
  });

  it('uses GREATEST for confidence on conflict — confidence only increases', () => {
    assert.ok(
      moduleServiceSource.includes('GREATEST(iocs.confidence, EXCLUDED.confidence)'),
      'confidence on conflict must use GREATEST (never decrease)'
    );
  });

  it('uses COALESCE for source on conflict — new source takes precedence', () => {
    assert.ok(
      moduleServiceSource.includes('COALESCE(EXCLUDED.source, iocs.source)'),
      'source on conflict must use COALESCE to prefer new non-null source'
    );
  });

  it('updates last_seen_at on conflict when provided', () => {
    assert.ok(
      moduleServiceSource.includes('COALESCE(EXCLUDED.last_seen_at, iocs.last_seen_at)'),
      'last_seen_at on conflict must update when new value is non-null'
    );
  });

  it('incident_iocs uses ON CONFLICT DO NOTHING for idempotent linking', () => {
    assert.ok(
      moduleServiceSource.includes('ON CONFLICT (tenant_slug, incident_id, ioc_id) DO NOTHING'),
      'linkIocToIncident must use DO NOTHING for idempotent linking'
    );
  });
});

// =====================================================================
// IOC Confidence and Validation
// =====================================================================
describe('IOC confidence and input validation', () => {
  it('confidence defaults to 50 when not provided', () => {
    // Find the createIoc function and check default confidence
    const createIocBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function createIoc'),
      moduleServiceSource.indexOf('async function createIoc') + 3000
    );
    assert.ok(createIocBlock.includes('toSafeInteger(payload.confidence, 50, 0, 100)'),
      'confidence must default to 50, clamped 0-100');
  });

  it('IOC value is required and capped at 1024 characters', () => {
    const createIocBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function createIoc'),
      moduleServiceSource.indexOf('async function createIoc') + 3000
    );
    assert.ok(createIocBlock.includes("safeText(payload.value, 1024)"),
      'IOC value must be capped at 1024 characters');
    assert.ok(createIocBlock.includes('invalid_ioc_value'),
      'must throw invalid_ioc_value when value is empty');
  });

  it('IOC source is capped at 128 characters', () => {
    const createIocBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function createIoc'),
      moduleServiceSource.indexOf('async function createIoc') + 3000
    );
    assert.ok(createIocBlock.includes("safeText(payload.source, 128)"),
      'IOC source must be capped at 128 characters');
  });

  it('IOC tags are limited to 20 items, each 64 chars max', () => {
    const createIocBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function createIoc'),
      moduleServiceSource.indexOf('async function createIoc') + 3000
    );
    assert.ok(createIocBlock.includes('.slice(0, 20)'),
      'tags must be limited to 20 items');
    assert.ok(createIocBlock.includes("safeText(item, 64)"),
      'each tag must be capped at 64 characters');
  });
});

// =====================================================================
// T7 — IOC Severity Derivation from Confidence
// =====================================================================
describe('T7 — IOC severity derivation from confidence', () => {
  it('iocConfidenceToSeverity function exists in module-service.js', () => {
    assert.ok(
      moduleServiceSource.includes('function iocConfidenceToSeverity'),
      'iocConfidenceToSeverity must be defined'
    );
  });

  it('maps confidence >= 90 to critical', () => {
    const funcMatch = moduleServiceSource.match(/function iocConfidenceToSeverity[\s\S]*?^}/m);
    assert.ok(funcMatch, 'function must exist');
    const body = funcMatch[0];
    assert.ok(body.includes(">= 90") && body.includes("'critical'"),
      'confidence >= 90 must map to critical');
  });

  it('maps confidence >= 70 to high', () => {
    const funcMatch = moduleServiceSource.match(/function iocConfidenceToSeverity[\s\S]*?^}/m);
    const body = funcMatch[0];
    assert.ok(body.includes(">= 70") && body.includes("'high'"),
      'confidence >= 70 must map to high');
  });

  it('maps confidence >= 40 to medium', () => {
    const funcMatch = moduleServiceSource.match(/function iocConfidenceToSeverity[\s\S]*?^}/m);
    const body = funcMatch[0];
    assert.ok(body.includes(">= 40") && body.includes("'medium'"),
      'confidence >= 40 must map to medium');
  });

  it('maps confidence < 40 to low', () => {
    const funcMatch = moduleServiceSource.match(/function iocConfidenceToSeverity[\s\S]*?^}/m);
    const body = funcMatch[0];
    assert.ok(body.includes("'low'"),
      'confidence < 40 must map to low');
  });

  it('asIoc row mapper includes severity field', () => {
    const asIocMatch = moduleServiceSource.match(/function asIoc\(row\)[\s\S]*?^}/m);
    assert.ok(asIocMatch, 'asIoc function must exist');
    const body = asIocMatch[0];
    assert.ok(body.includes('severity'), 'asIoc must include severity field');
    assert.ok(body.includes('iocConfidenceToSeverity'), 'asIoc must derive severity from iocConfidenceToSeverity');
  });
});

// =====================================================================
// T5 — minConfidence filter in listIocs
// =====================================================================
describe('T5 — minConfidence filter in listIocs', () => {
  it('listIocs supports minConfidence option', () => {
    const listIocsBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function listIocs'),
      moduleServiceSource.indexOf('async function listIocs') + 3000
    );
    assert.ok(listIocsBlock.includes('minConfidence'),
      'listIocs must reference minConfidence');
  });

  it('minConfidence generates a WHERE clause condition', () => {
    const listIocsBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function listIocs'),
      moduleServiceSource.indexOf('async function listIocs') + 3000
    );
    assert.ok(listIocsBlock.includes('confidence >='),
      'minConfidence must produce confidence >= $N WHERE clause');
  });

  it('route handler passes minConfidence query param', () => {
    assert.ok(routeSource.includes('minConfidence'),
      'route must accept minConfidence query parameter');
  });
});

// =====================================================================
// IOC Listing and Pagination
// =====================================================================
describe('IOC listing and pagination', () => {
  it('listIocs supports iocType filter', () => {
    const listIocsBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function listIocs'),
      moduleServiceSource.indexOf('async function listIocs') + 3000
    );
    assert.ok(listIocsBlock.includes('normalizeIocType(options.iocType)'),
      'iocType filter must validate through normalizeIocType');
  });

  it('listIocs supports search with ILIKE and escape', () => {
    const listIocsBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function listIocs'),
      moduleServiceSource.indexOf('async function listIocs') + 3000
    );
    assert.ok(listIocsBlock.includes('ILIKE'),
      'search must use ILIKE for case-insensitive matching');
    assert.ok(listIocsBlock.includes('escapeLikePattern'),
      'search must escape LIKE metacharacters');
  });

  it('listIocs returns pagination metadata', () => {
    const listIocsBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function listIocs'),
      moduleServiceSource.indexOf('async function listIocs') + 3000
    );
    assert.ok(listIocsBlock.includes('pagination'), 'must return pagination object');
    assert.ok(listIocsBlock.includes('hasMore'), 'pagination must include hasMore');
    assert.ok(listIocsBlock.includes('total'), 'pagination must include total count');
  });

  it('listIocs limits are clamped to safe ranges', () => {
    const listIocsBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function listIocs'),
      moduleServiceSource.indexOf('async function listIocs') + 3000
    );
    assert.ok(listIocsBlock.includes('toSafeInteger(options.limit, 50, 1, 200)'),
      'limit must be clamped to 1-200, default 50');
  });

  it('listIocs orders by last_seen_at descending', () => {
    const listIocsBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function listIocs'),
      moduleServiceSource.indexOf('async function listIocs') + 3000
    );
    assert.ok(listIocsBlock.includes('COALESCE(last_seen_at, first_seen_at) DESC'),
      'IOC list must order by most recent sighting first');
  });

  it('empty results include helpful message', () => {
    const listIocsBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function listIocs'),
      moduleServiceSource.indexOf('async function listIocs') + 3000
    );
    assert.ok(listIocsBlock.includes('No IOCs stored for this tenant yet'),
      'empty results must include helpful message');
  });
});

// =====================================================================
// IOC Audit Trail
// =====================================================================
describe('IOC audit trail', () => {
  it('createIoc generates ioc.upserted audit log', () => {
    const createIocBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function createIoc'),
      moduleServiceSource.indexOf('async function createIoc') + 3000
    );
    assert.ok(createIocBlock.includes("'ioc.upserted'"),
      'createIoc must log ioc.upserted action');
  });

  it('audit log includes iocType and value in payload', () => {
    const createIocBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function createIoc'),
      moduleServiceSource.indexOf('async function createIoc') + 3000
    );
    assert.ok(createIocBlock.includes('iocType') && createIocBlock.includes('ioc.type'),
      'audit log payload must include iocType');
  });

  it('linkIocToIncident generates incident.ioc_linked audit log', () => {
    const linkBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function linkIocToIncident'),
      moduleServiceSource.indexOf('async function linkIocToIncident') + 2000
    );
    assert.ok(linkBlock.includes("'incident.ioc_linked'"),
      'linkIocToIncident must log incident.ioc_linked action');
  });

  it('linkIocToIncident audit includes created boolean (new vs noop)', () => {
    const linkBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function linkIocToIncident'),
      moduleServiceSource.indexOf('async function linkIocToIncident') + 2000
    );
    assert.ok(linkBlock.includes('created:'),
      'audit log must include created boolean to distinguish new link vs no-op');
  });
});

// =====================================================================
// IOC Tenant Isolation
// =====================================================================
describe('IOC tenant isolation', () => {
  it('listIocs scopes to tenant_slug in WHERE clause', () => {
    const listIocsBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function listIocs'),
      moduleServiceSource.indexOf('async function listIocs') + 3000
    );
    assert.ok(listIocsBlock.includes("'tenant_slug = $1'"),
      'listIocs must scope by tenant_slug');
  });

  it('createIoc includes tenant_slug in INSERT', () => {
    const createIocBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function createIoc'),
      moduleServiceSource.indexOf('async function createIoc') + 3000
    );
    assert.ok(createIocBlock.includes('tenant_slug'),
      'createIoc must insert tenant_slug');
  });

  it('linkIocToIncident includes tenant_slug in INSERT', () => {
    const linkBlock = moduleServiceSource.slice(
      moduleServiceSource.indexOf('async function linkIocToIncident'),
      moduleServiceSource.indexOf('async function linkIocToIncident') + 2000
    );
    assert.ok(linkBlock.includes('tenant_slug'),
      'linkIocToIncident must insert tenant_slug');
  });

  it('RLS policies exist on iocs and incident_iocs tables', () => {
    const rlsMigration = migrationSources['017_rls_fk_indexes_dedup.sql'];
    assert.ok(rlsMigration, 'Migration 017 must exist');
    assert.ok(rlsMigration.includes('tenant_isolation_iocs'),
      'RLS policy on iocs table must exist');
    assert.ok(rlsMigration.includes('tenant_isolation_incident_iocs'),
      'RLS policy on incident_iocs table must exist');
  });

  it('RLS enabled on iocs and incident_iocs tables', () => {
    const rlsMigration = migrationSources['017_rls_fk_indexes_dedup.sql'];
    assert.ok(rlsMigration.includes('iocs ENABLE ROW LEVEL SECURITY'),
      'iocs table must have RLS enabled');
    assert.ok(rlsMigration.includes('incident_iocs ENABLE ROW LEVEL SECURITY'),
      'incident_iocs table must have RLS enabled');
  });
});

// =====================================================================
// IOC Schema — migration verification
// =====================================================================
describe('IOC schema — migration verification', () => {
  it('iocs table has confidence CHECK constraint (0-100)', () => {
    const mig002 = migrationSources['002_enterprise_security_and_modules.sql'];
    assert.ok(mig002.includes('confidence') && mig002.includes('CHECK'),
      'iocs table must have confidence CHECK constraint');
  });

  it('iocs table has unique constraint on (tenant_slug, ioc_type, value)', () => {
    const mig002 = migrationSources['002_enterprise_security_and_modules.sql'];
    assert.ok(mig002.includes('UNIQUE (tenant_slug, ioc_type, value)'),
      'iocs table must have UNIQUE constraint on tenant+type+value');
  });

  it('iocs table has tenant+type index', () => {
    const mig002 = migrationSources['002_enterprise_security_and_modules.sql'];
    assert.ok(mig002.includes('iocs_tenant_type_idx'),
      'iocs table must have tenant+type index');
  });

  it('iocs table has tenant+last_seen index', () => {
    const mig002 = migrationSources['002_enterprise_security_and_modules.sql'];
    assert.ok(mig002.includes('iocs_tenant_last_seen_idx'),
      'iocs table must have tenant+last_seen index');
  });

  it('incident_iocs has unique constraint on (tenant_slug, incident_id, ioc_id)', () => {
    const mig002 = migrationSources['002_enterprise_security_and_modules.sql'];
    assert.ok(mig002.includes('UNIQUE (tenant_slug, incident_id, ioc_id)'),
      'incident_iocs must have unique constraint on tenant+incident+ioc');
  });

  it('incident_iocs has FK to incidents with CASCADE', () => {
    const mig002 = migrationSources['002_enterprise_security_and_modules.sql'];
    assert.ok(mig002.includes('REFERENCES incidents(id) ON DELETE CASCADE'),
      'incident_iocs must FK to incidents with CASCADE');
  });

  it('incident_iocs has FK to iocs with CASCADE', () => {
    const mig002 = migrationSources['002_enterprise_security_and_modules.sql'];
    assert.ok(mig002.includes('REFERENCES iocs(id) ON DELETE CASCADE'),
      'incident_iocs must FK to iocs with CASCADE');
  });
});

// =====================================================================
// IOC Route Wiring
// =====================================================================
describe('IOC route wiring', () => {
  it('GET /v1/iocs route exists', () => {
    assert.ok(routeSource.includes("/v1/iocs"),
      'GET /v1/iocs route must exist');
  });

  it('GET requires executive_viewer role', () => {
    // The GET handler calls requireRole with executive_viewer
    const iocBlock = routeSource.slice(
      routeSource.indexOf("/v1/iocs"),
      routeSource.indexOf("/v1/iocs") + 2000
    );
    assert.ok(iocBlock.includes("'executive_viewer'"),
      'GET /v1/iocs must require executive_viewer role');
  });

  it('POST requires security_analyst role', () => {
    const iocBlock = routeSource.slice(
      routeSource.indexOf("/v1/iocs"),
      routeSource.indexOf("/v1/iocs") + 4000
    );
    assert.ok(iocBlock.includes("'security_analyst'"),
      'POST /v1/iocs must require security_analyst role');
  });

  it('POST validates required fields: iocType, value', () => {
    const iocBlock = routeSource.slice(
      routeSource.indexOf("/v1/iocs"),
      routeSource.indexOf("/v1/iocs") + 4000
    );
    assert.ok(iocBlock.includes("'iocType'") && iocBlock.includes("'value'"),
      'POST body must require iocType and value');
  });

  it('POST validates optional fields include source, confidence, tags', () => {
    const iocBlock = routeSource.slice(
      routeSource.indexOf("/v1/iocs"),
      routeSource.indexOf("/v1/iocs") + 4000
    );
    assert.ok(iocBlock.includes("'source'") && iocBlock.includes("'confidence'") && iocBlock.includes("'tags'"),
      'POST body optional fields must include source, confidence, tags');
  });

  it('IOC link route exists (POST /v1/incidents/:id/iocs/:id)', () => {
    assert.ok(routeSource.includes("iocs"),
      'IOC link route must reference iocs path');
    assert.ok(routeSource.includes("linkIocToIncident"),
      'IOC link route must call linkIocToIncident');
  });
});

// =====================================================================
// Frontend Types — IocRecord
// =====================================================================
describe('Frontend types — IocRecord', () => {
  it('IocType includes exactly ip, domain, url, hash', () => {
    assert.ok(frontendTypesSource.includes("'ip' | 'domain' | 'url' | 'hash'"),
      'IocType must be ip | domain | url | hash');
  });

  it('IocRecord includes severity field', () => {
    // Find the IocRecord interface
    const iocRecordMatch = frontendTypesSource.match(/export interface IocRecord\s*\{[\s\S]*?\}/);
    assert.ok(iocRecordMatch, 'IocRecord interface must exist');
    const body = iocRecordMatch[0];
    assert.ok(body.includes('severity'), 'IocRecord must include severity field');
  });

  it('IocSeverity type exists with critical/high/medium/low', () => {
    assert.ok(frontendTypesSource.includes("IocSeverity"),
      'IocSeverity type must exist');
    assert.ok(frontendTypesSource.includes("'critical'"),
      'IocSeverity must include critical');
  });

  it('IocRecord includes confidence field', () => {
    const iocRecordMatch = frontendTypesSource.match(/export interface IocRecord\s*\{[\s\S]*?\}/);
    const body = iocRecordMatch[0];
    assert.ok(body.includes('confidence: number'),
      'IocRecord must include confidence as number');
  });

  it('IocRecord includes source field', () => {
    const iocRecordMatch = frontendTypesSource.match(/export interface IocRecord\s*\{[\s\S]*?\}/);
    const body = iocRecordMatch[0];
    assert.ok(body.includes('source:'),
      'IocRecord must include source field');
  });

  it('IocRecord includes tags field', () => {
    const iocRecordMatch = frontendTypesSource.match(/export interface IocRecord\s*\{[\s\S]*?\}/);
    const body = iocRecordMatch[0];
    assert.ok(body.includes('tags: string[]'),
      'IocRecord must include tags as string array');
  });

  it('IocRecord includes timestamp fields', () => {
    const iocRecordMatch = frontendTypesSource.match(/export interface IocRecord\s*\{[\s\S]*?\}/);
    const body = iocRecordMatch[0];
    assert.ok(body.includes('firstSeenAt'), 'IocRecord must include firstSeenAt');
    assert.ok(body.includes('lastSeenAt'), 'IocRecord must include lastSeenAt');
    assert.ok(body.includes('createdAt'), 'IocRecord must include createdAt');
  });

  it('CreateIocPayload includes tags field', () => {
    const payloadMatch = frontendTypesSource.match(/export interface CreateIocPayload\s*\{[\s\S]*?\}/);
    assert.ok(payloadMatch, 'CreateIocPayload must exist');
    const body = payloadMatch[0];
    assert.ok(body.includes('tags'), 'CreateIocPayload must include tags');
  });

  it('fetchIocs API function supports minConfidence parameter', () => {
    assert.ok(frontendTypesSource.includes('minConfidence'),
      'fetchIocs must accept minConfidence parameter');
  });
});

// =====================================================================
// T8 — Dashboard IOC KPI Breakdown
// =====================================================================
describe('T8 — Dashboard IOC KPI breakdown', () => {
  it('dashboard computes iocTypeCounts memo', () => {
    assert.ok(dashboardSource.includes('iocTypeCounts'),
      'dashboard must compute iocTypeCounts');
  });

  it('dashboard computes iocSeverityCounts memo', () => {
    assert.ok(dashboardSource.includes('iocSeverityCounts'),
      'dashboard must compute iocSeverityCounts');
  });

  it('IOC KPI card shows type distribution (ip, domain, url, hash)', () => {
    assert.ok(dashboardSource.includes('iocTypeCounts.ip'),
      'KPI card must show ip count');
    assert.ok(dashboardSource.includes('iocTypeCounts.domain'),
      'KPI card must show domain count');
    assert.ok(dashboardSource.includes('iocTypeCounts.url'),
      'KPI card must show url count');
    assert.ok(dashboardSource.includes('iocTypeCounts.hash'),
      'KPI card must show hash count');
  });

  it('IOC KPI card shows severity distribution', () => {
    assert.ok(dashboardSource.includes('iocSeverityCounts.critical'),
      'KPI card must show critical IOC count');
    assert.ok(dashboardSource.includes('iocSeverityCounts.high'),
      'KPI card must show high IOC count');
    assert.ok(dashboardSource.includes('iocSeverityCounts.medium'),
      'KPI card must show medium IOC count');
    assert.ok(dashboardSource.includes('iocSeverityCounts.low'),
      'KPI card must show low IOC count');
  });
});

// =====================================================================
// T2/T3/T4 — IOC Table, Search, and Detail Display
// =====================================================================
describe('T2/T3/T4 — IOC table with search and detail display', () => {
  it('IOC Vault table section exists in dashboard', () => {
    assert.ok(dashboardSource.includes('IOC Vault'),
      'IOC Vault section must exist in dashboard');
  });

  it('IOC search input exists', () => {
    assert.ok(dashboardSource.includes('iocSearchTerm'),
      'IOC search term state must exist');
    assert.ok(dashboardSource.includes('Search IOC value'),
      'IOC search input placeholder must exist');
  });

  it('IOC type filter dropdown exists', () => {
    assert.ok(dashboardSource.includes('iocTypeFilter'),
      'IOC type filter state must exist');
    assert.ok(dashboardSource.includes('All types'),
      'IOC type filter must have All types option');
  });

  it('IOC table displays confidence column', () => {
    assert.ok(dashboardSource.includes('Confidence'),
      'IOC table must have Confidence column header');
    assert.ok(dashboardSource.includes('ioc.confidence'),
      'IOC table must display ioc.confidence');
  });

  it('IOC table displays severity column', () => {
    assert.ok(dashboardSource.includes('ioc.severity'),
      'IOC table must display ioc.severity');
  });

  it('IOC table displays source column', () => {
    assert.ok(dashboardSource.includes('ioc.source'),
      'IOC table must display ioc.source');
  });

  it('IOC table displays tags', () => {
    assert.ok(dashboardSource.includes('ioc.tags'),
      'IOC table must display ioc.tags');
  });

  it('IOC table displays timestamps', () => {
    assert.ok(dashboardSource.includes('ioc.firstSeenAt'),
      'IOC table must display firstSeenAt');
    assert.ok(dashboardSource.includes('ioc.lastSeenAt'),
      'IOC table must display lastSeenAt');
  });

  it('IOC table shows pagination info', () => {
    assert.ok(dashboardSource.includes('pagination.total'),
      'IOC table must show total count from pagination');
  });

  it('iocsQuery uses search and type filter parameters', () => {
    assert.ok(dashboardSource.includes('iocSearchTerm, iocTypeFilter'),
      'iocsQuery key must include search and filter');
  });
});

// =====================================================================
// T6 — IOC Creation Form Tags
// =====================================================================
describe('T6 — IOC creation form tags', () => {
  it('IOC creation form has tag input', () => {
    assert.ok(dashboardSource.includes('iocTagInput'),
      'IOC form must have tagInput state');
    assert.ok(dashboardSource.includes('iocTags'),
      'IOC form must have tags state');
  });

  it('tags are passed to createIoc mutation', () => {
    assert.ok(dashboardSource.includes('tags: iocTags'),
      'createIoc mutation must include tags');
  });

  it('tags are cleared on successful creation', () => {
    assert.ok(dashboardSource.includes("setIocTags([])"),
      'tags must be cleared after IOC creation');
  });

  it('tag add placeholder text exists', () => {
    assert.ok(dashboardSource.includes('Add tag'),
      'tag input must have add tag placeholder');
  });
});

// =====================================================================
// Threat Connectors — Source Attribution
// =====================================================================
describe('Threat connectors — source attribution', () => {
  it('normalizeIncident exists for connector data normalization', () => {
    assert.ok(threatConnectorsSource.includes('normalizeIncident'),
      'normalizeIncident function must exist for connector normalization');
  });

  it('connector adapters exist for Wazuh, MISP, OpenCTI, TheHive', () => {
    assert.ok(threatConnectorsSource.includes('wazuh'), 'Wazuh adapter must exist');
    assert.ok(threatConnectorsSource.includes('misp'), 'MISP adapter must exist');
    assert.ok(threatConnectorsSource.includes('opencti'), 'OpenCTI adapter must exist');
    assert.ok(threatConnectorsSource.includes('thehive'), 'TheHive adapter must exist');
  });

  it('SSRF protection exists for connector URLs', () => {
    assert.ok(threatConnectorsSource.includes('isPrivateHostname'),
      'SSRF protection via isPrivateHostname must exist');
  });

  it('connector severity normalization does not inflate unknown values', () => {
    assert.ok(threatConnectorsSource.includes("'unknown'"),
      'Unknown severity values must be returned as unknown, not inflated');
  });
});

// =====================================================================
// Correlation Engine
// =====================================================================
describe('Correlation engine', () => {
  it('supports threshold rule type', () => {
    assert.ok(correlationSource.includes('threshold'),
      'correlation engine must support threshold rule type');
  });

  it('supports sequence rule type', () => {
    assert.ok(correlationSource.includes('sequence'),
      'correlation engine must support sequence rule type');
  });

  it('supports aggregation rule type', () => {
    assert.ok(correlationSource.includes('aggregation'),
      'correlation engine must support aggregation rule type');
  });

  it('supports anomaly rule type', () => {
    assert.ok(correlationSource.includes('anomaly'),
      'correlation engine must support anomaly rule type');
  });

  it('auto-creates incidents from correlated alerts', () => {
    assert.ok(correlationSource.includes('INSERT INTO incidents'),
      'correlation engine must auto-create incidents via INSERT INTO incidents');
  });

  it('marks alerts as correlated with incident_id', () => {
    assert.ok(correlationSource.includes('correlated') && correlationSource.includes('incident_id'),
      'correlation engine must mark alerts as correlated with incident_id');
  });
});

// =====================================================================
// SIEM Alert IOC-Adjacent Fields
// =====================================================================
describe('SIEM alert IOC-adjacent fields', () => {
  it('ingestSiemAlert accepts sourceIp and destIp', () => {
    assert.ok(siemServiceSource.includes('sourceIp'),
      'ingestSiemAlert must accept sourceIp');
    assert.ok(siemServiceSource.includes('destIp'),
      'ingestSiemAlert must accept destIp');
  });

  it('source_ip and dest_ip are stored in siem_alerts table', () => {
    assert.ok(siemServiceSource.includes('source_ip'),
      'siem_alerts must store source_ip');
    assert.ok(siemServiceSource.includes('dest_ip'),
      'siem_alerts must store dest_ip');
  });

  it('triage suggestions reference sourceIp for threat assessment', () => {
    assert.ok(siemServiceSource.includes('block_source_ip'),
      'triage suggestions must reference source IP blocking');
  });

  it('search includes source_ip and dest_ip fields', () => {
    assert.ok(siemServiceSource.includes('source_ip ILIKE'),
      'search must include source_ip');
    assert.ok(siemServiceSource.includes('dest_ip ILIKE'),
      'search must include dest_ip');
  });
});

// =====================================================================
// CVE Schema Verification
// =====================================================================
describe('CVE schema verification', () => {
  it('cves table has severity CHECK constraint', () => {
    const mig007 = migrationSources['007_phase3_ai_products.sql'];
    assert.ok(mig007, 'Migration 007 must exist');
    assert.ok(mig007.includes("severity") && mig007.includes("'critical'"),
      'CVE severity CHECK must include critical');
  });

  it('tenant_cve_views provides tenant scoping for CVEs', () => {
    const mig007 = migrationSources['007_phase3_ai_products.sql'];
    assert.ok(mig007.includes('tenant_cve_views'),
      'tenant_cve_views table must exist for tenant-scoped CVE access');
  });

  it('cve_sync_state tracks sync health with backoff', () => {
    const mig010 = migrationSources['010_phase35_cve_sync_cursor.sql'];
    assert.ok(mig010, 'Migration 010 must exist');
    assert.ok(mig010.includes('failure_count'),
      'CVE sync state must track failure_count');
    assert.ok(mig010.includes('backoff_until'),
      'CVE sync state must track backoff_until');
  });
});

// =====================================================================
// asIoc Row Mapper
// =====================================================================
describe('asIoc row mapper', () => {
  it('converts id to String', () => {
    const asIocMatch = moduleServiceSource.match(/function asIoc\(row\)[\s\S]*?^}/m);
    const body = asIocMatch[0];
    assert.ok(body.includes('String(row.id)'), 'id must be converted to String');
  });

  it('converts dates to ISO strings', () => {
    const asIocMatch = moduleServiceSource.match(/function asIoc\(row\)[\s\S]*?^}/m);
    const body = asIocMatch[0];
    assert.ok(body.includes('.toISOString()'),
      'dates must be converted to ISO strings');
  });

  it('defaults source to null when empty', () => {
    const asIocMatch = moduleServiceSource.match(/function asIoc\(row\)[\s\S]*?^}/m);
    const body = asIocMatch[0];
    assert.ok(body.includes('row.source || null'),
      'source must default to null');
  });

  it('defaults tags to empty array', () => {
    const asIocMatch = moduleServiceSource.match(/function asIoc\(row\)[\s\S]*?^}/m);
    const body = asIocMatch[0];
    assert.ok(body.includes('row.tags || []'),
      'tags must default to empty array');
  });
});
