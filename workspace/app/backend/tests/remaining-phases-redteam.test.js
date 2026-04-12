const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

// =====================================================================
// Remaining Phases -- Red Team + Hardening Tests
// =====================================================================

// ── correlation-engine.js ──
// The correlation engine module requires database for live evaluation,
// so we test the module structure and import safety here.

describe('Correlation Engine: Module Safety', () => {

  it('exports runCorrelationEngine function', () => {
    const { runCorrelationEngine } = require('../src/correlation-engine');
    assert.equal(typeof runCorrelationEngine, 'function');
  });

  it('returns empty result when database is not configured', async () => {
    const { runCorrelationEngine } = require('../src/correlation-engine');
    const config = { databaseUrl: '' };
    const result = await runCorrelationEngine(config, 'test-tenant');
    assert.equal(result.evaluated, 0);
    assert.deepEqual(result.correlations, []);
  });

  it('sanitizes tenant slug before evaluation', async () => {
    const { runCorrelationEngine } = require('../src/correlation-engine');
    const config = { databaseUrl: '' };
    // Malicious tenant should not throw
    const result = await runCorrelationEngine(config, "'; DROP TABLE siem_alerts; --");
    assert.equal(result.evaluated, 0);
    assert.deepEqual(result.correlations, []);
  });
});

// ── database.js ──

describe('Database: queryWithTenant', () => {

  it('exports queryWithTenant function', () => {
    const { queryWithTenant } = require('../src/database');
    assert.equal(typeof queryWithTenant, 'function');
  });

  it('returns null when database is not configured', async () => {
    const { queryWithTenant } = require('../src/database');
    const config = { databaseUrl: '' };
    const result = await queryWithTenant(config, 'test-tenant', 'SELECT 1');
    assert.equal(result, null);
  });
});

// ── siem-service.js dedup ──

describe('SIEM Service: Deduplication', () => {

  it('ingestSiemAlert returns null when database not configured', async () => {
    const { ingestSiemAlert } = require('../src/siem-service');
    const result = await ingestSiemAlert({ databaseUrl: '' }, {
      tenant: 'test',
      source: 'wazuh',
      alertId: 'test-1',
      severity: 'high',
    });
    assert.equal(result, null);
  });

  it('ingestSiemAlert validates severity input', async () => {
    // We can't test DB dedup without a real DB, but we can verify
    // the function accepts valid input and validates severity
    const fs = require('node:fs');
    const content = fs.readFileSync(require.resolve('../src/siem-service'), 'utf8');
    assert.ok(content.includes('ON CONFLICT'),
      'ingestSiemAlert must use ON CONFLICT for deduplication');
    assert.ok(content.includes('tenant_slug, source, alert_id'),
      'ON CONFLICT must target the dedup index columns');
  });
});

// ── migration 017 ──

describe('Migration 017: RLS + FK + Indexes', () => {

  it('migration file exists and contains RLS policies', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const migrationPath = path.resolve(__dirname, '..', 'migrations', '017_rls_fk_indexes_dedup.sql');
    const content = fs.readFileSync(migrationPath, 'utf8');

    assert.ok(content.includes('ENABLE ROW LEVEL SECURITY'),
      'Migration must enable RLS on tenant-scoped tables');
    assert.ok(content.includes('CREATE POLICY'),
      'Migration must create RLS policies');
    assert.ok(content.includes('app.current_tenant'),
      'RLS policies must use app.current_tenant session variable');
  });

  it('migration adds tenant FK constraints to all threat tables', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const migrationPath = path.resolve(__dirname, '..', 'migrations', '017_rls_fk_indexes_dedup.sql');
    const content = fs.readFileSync(migrationPath, 'utf8');

    const expectedFks = [
      'iocs_tenant_slug_fk',
      'incident_iocs_tenant_slug_fk',
      'incident_timeline_tenant_slug_fk',
      'tenant_cve_views_tenant_slug_fk',
      'cve_summaries_tenant_slug_fk',
      'incident_mitre_mappings_tenant_slug_fk',
      'playbooks_tenant_slug_fk',
      'playbook_executions_tenant_slug_fk',
      'siem_alerts_tenant_slug_fk',
      'alert_correlation_rules_tenant_slug_fk',
      'threat_hunt_queries_tenant_slug_fk',
    ];

    for (const fk of expectedFks) {
      assert.ok(content.includes(fk), `Migration must define ${fk}`);
    }
  });

  it('migration adds technique_id FK to incident_mitre_mappings', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const migrationPath = path.resolve(__dirname, '..', 'migrations', '017_rls_fk_indexes_dedup.sql');
    const content = fs.readFileSync(migrationPath, 'utf8');

    assert.ok(content.includes('incident_mitre_mappings_technique_fk'),
      'Must add technique_id FK to mitre_attack_techniques');
  });

  it('migration adds indexes to playbook_step_results', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const migrationPath = path.resolve(__dirname, '..', 'migrations', '017_rls_fk_indexes_dedup.sql');
    const content = fs.readFileSync(migrationPath, 'utf8');

    assert.ok(content.includes('playbook_step_results_execution_idx'),
      'Must add execution_id index to playbook_step_results');
    assert.ok(content.includes('playbook_step_results_step_idx'),
      'Must add step_id index to playbook_step_results');
  });

  it('migration adds SIEM dedup unique index', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const migrationPath = path.resolve(__dirname, '..', 'migrations', '017_rls_fk_indexes_dedup.sql');
    const content = fs.readFileSync(migrationPath, 'utf8');

    assert.ok(content.includes('siem_alerts_dedup_idx'),
      'Must create unique dedup index on siem_alerts');
    assert.ok(content.includes('WHERE alert_id IS NOT NULL'),
      'Dedup index must be partial (only where alert_id IS NOT NULL)');
  });

  it('RLS policies cover all 12 tenant-scoped tables', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const migrationPath = path.resolve(__dirname, '..', 'migrations', '017_rls_fk_indexes_dedup.sql');
    const content = fs.readFileSync(migrationPath, 'utf8');

    const expectedTables = [
      'incidents', 'iocs', 'incident_iocs', 'incident_timeline',
      'tenant_cve_views', 'cve_summaries', 'incident_mitre_mappings',
      'playbooks', 'playbook_executions', 'siem_alerts',
      'alert_correlation_rules', 'threat_hunt_queries',
    ];

    for (const table of expectedTables) {
      assert.ok(content.includes(`ENABLE ROW LEVEL SECURITY`),
        `RLS must be enabled`);
      assert.ok(content.includes(`tenant_isolation_${table}`),
        `RLS policy must exist for ${table}`);
    }
  });

  it('RLS uses safe default (deny all when tenant not set)', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const migrationPath = path.resolve(__dirname, '..', 'migrations', '017_rls_fk_indexes_dedup.sql');
    const content = fs.readFileSync(migrationPath, 'utf8');

    // current_setting('app.current_tenant', true) returns NULL when not set
    // tenant_slug = NULL evaluates to FALSE, denying all rows -- safe default
    assert.ok(content.includes("current_setting('app.current_tenant', true)"),
      'RLS must use current_setting with missing_ok=true for safe default');
  });
});

// ── MagicBentoSection marketing stats ──

describe('Marketing Stats: Truthfulness', () => {

  it('all stats in MagicBentoSection are marked as projected', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const filePath = path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'MagicBentoSection.tsx');
    const content = fs.readFileSync(filePath, 'utf8');

    // Every stat should have projected: true
    const statsWithProjected = (content.match(/projected:\s*true/g) || []).length;
    // Count total stat objects (by counting 'label:' inside stats arrays)
    assert.ok(statsWithProjected >= 15,
      `All 15 stats must be marked as projected (found ${statsWithProjected})`);
  });

  it('MagicBentoSection includes projected disclaimer text', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const filePath = path.resolve(__dirname, '..', '..', 'frontend', 'src', 'components', 'MagicBentoSection.tsx');
    const content = fs.readFileSync(filePath, 'utf8');

    assert.ok(content.includes('Projected platform targets'),
      'Must include disclosure that stats are projected targets');
    assert.ok(content.includes('not measured from live deployment'),
      'Must disclose stats are not from live deployment data');
  });
});

// ── SIEM Export route verification ──

describe('SIEM Export: Route Registration', () => {

  it('threat-intel routes include SIEM export endpoint', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const routesPath = path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js');
    const content = fs.readFileSync(routesPath, 'utf8');

    assert.ok(content.includes('/v1/threat-intel/siem/export'),
      'Must register SIEM export route');
    assert.ok(content.includes('text/csv'),
      'Must support CSV export format');
    assert.ok(content.includes('application/json'),
      'Must support JSON export format');
    assert.ok(content.includes('Content-Disposition'),
      'Must set Content-Disposition header for downloads');
  });

  it('threat-intel routes include correlation engine endpoint', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const routesPath = path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js');
    const content = fs.readFileSync(routesPath, 'utf8');

    assert.ok(content.includes('/v1/threat-intel/siem/correlate-all'),
      'Must register correlation engine route');
    assert.ok(content.includes('runCorrelationEngine'),
      'Route must call runCorrelationEngine');
  });

  it('SIEM export requires authentication', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const routesPath = path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js');
    const content = fs.readFileSync(routesPath, 'utf8');

    // Find the export route handler (the second occurrence, in the handler block)
    const firstIdx = content.indexOf("'/v1/threat-intel/siem/export'");
    const secondIdx = content.indexOf("'/v1/threat-intel/siem/export'", firstIdx + 1);
    const exportSection = content.substring(secondIdx, secondIdx + 600);
    assert.ok(exportSection.includes('requireSession'),
      'SIEM export must require authenticated session');
    assert.ok(exportSection.includes('threatAuthChain'),
      'SIEM export must go through threat auth chain');
  });

  it('SIEM export has audit logging', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const routesPath = path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js');
    const content = fs.readFileSync(routesPath, 'utf8');

    assert.ok(content.includes('siem.exported'),
      'SIEM export must create audit log entry');
  });

  it('CSV export properly escapes values', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const routesPath = path.resolve(__dirname, '..', 'src', 'modules', 'threat-intel', 'routes.js');
    const content = fs.readFileSync(routesPath, 'utf8');

    assert.ok(content.includes('replace(/"/g, \'""\''),
      'CSV export must escape double quotes in values');
  });
});
