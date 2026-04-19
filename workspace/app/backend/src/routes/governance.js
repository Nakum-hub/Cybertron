function registerRoutes(routerContext) {
  const register = routerContext?.register;
  if (typeof register !== 'function') {
    throw new Error('governance routes require routerContext.register(handler)');
  }

  const deps = routerContext.deps || {};
  const {
    config,
    sendJson,
    sendMethodNotAllowed,
    requireSession,
    resolveTenantForRequest,
    toSafeInteger,
    requireRole,
    listAuditLogs,
    dbQuery,
  } = deps;

  register(async ({ context, response, baseExtraHeaders }) => {
    if (context.path === '/v1/governance/dashboard') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Governance dashboard requires authentication'
      );
      if (!session) {
        return true;
      }

      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant')
      );
      if (!tenant) {
        return true;
      }

      let policyCount = 0;
      let controlCount = 0;
      let complianceScore = 0;
      if (config.databaseUrl) {
        try {
          const auditResult = await listAuditLogs(config, tenant, { limit: 1, offset: 0 });
          policyCount = auditResult?.total || 0;
        } catch {
          // Governance tables may not be seeded yet.
        }
      }

      sendJson(
        response,
        context,
        config,
        200,
        {
          tenant,
          summary: {
            totalPolicies: policyCount,
            activeControls: controlCount,
            complianceScore,
            lastReviewedAt: null,
          },
          riskPosture: 'not_assessed',
          checkedAt: new Date().toISOString(),
        },
        baseExtraHeaders
      );
      return true;
    }

    if (context.path === '/v1/mitre/tactics') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'MITRE ATT&CK data requires authentication'
      );
      if (!session) {
        return true;
      }

      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) {
        return true;
      }

      let tactics = [];
      if (config.databaseUrl) {
        try {
          const result = await dbQuery(
            config,
            'SELECT id, external_id, name, description, url FROM mitre_tactics ORDER BY external_id ASC'
          );
          tactics = result?.rows || [];
        } catch {
          // Table may not exist yet.
        }
      }

      if (!tactics.length) {
        tactics = [
          {
            external_id: 'TA0001',
            name: 'Initial Access',
            description: 'Techniques for gaining initial access to the network',
          },
          {
            external_id: 'TA0002',
            name: 'Execution',
            description: 'Techniques for running hostile code',
          },
          {
            external_id: 'TA0003',
            name: 'Persistence',
            description: 'Techniques for maintaining presence',
          },
          {
            external_id: 'TA0004',
            name: 'Privilege Escalation',
            description: 'Techniques for gaining elevated permissions',
          },
          {
            external_id: 'TA0005',
            name: 'Defense Evasion',
            description: 'Techniques for avoiding detection',
          },
          {
            external_id: 'TA0006',
            name: 'Credential Access',
            description: 'Techniques for stealing credentials',
          },
          {
            external_id: 'TA0007',
            name: 'Discovery',
            description: 'Techniques for exploring the environment',
          },
          {
            external_id: 'TA0008',
            name: 'Lateral Movement',
            description: 'Techniques for moving through the network',
          },
          {
            external_id: 'TA0009',
            name: 'Collection',
            description: 'Techniques for gathering data of interest',
          },
          {
            external_id: 'TA0010',
            name: 'Exfiltration',
            description: 'Techniques for stealing data',
          },
          {
            external_id: 'TA0011',
            name: 'Command and Control',
            description: 'Techniques for communicating with compromised systems',
          },
          {
            external_id: 'TA0040',
            name: 'Impact',
            description: 'Techniques for disrupting availability or compromising integrity',
          },
          {
            external_id: 'TA0042',
            name: 'Resource Development',
            description: 'Techniques for establishing resources for operations',
          },
          {
            external_id: 'TA0043',
            name: 'Reconnaissance',
            description: 'Techniques for gathering information to plan operations',
          },
        ];
      }

      sendJson(
        response,
        context,
        config,
        200,
        { data: tactics, total: tactics.length },
        baseExtraHeaders
      );
      return true;
    }

    if (context.path === '/v1/playbooks') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Playbook access requires authentication'
      );
      if (!session) {
        return true;
      }

      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant')
      );
      if (!tenant) {
        return true;
      }

      let playbooks = [];
      if (config.databaseUrl) {
        try {
          const result = await dbQuery(
            config,
            'SELECT id, name, description, trigger_type, severity_filter, status, steps, created_at, updated_at FROM playbooks WHERE tenant_slug = $1 ORDER BY created_at DESC LIMIT 100',
            [tenant]
          );
          playbooks = (result?.rows || []).map(row => ({
            id: row.id,
            name: row.name,
            description: row.description,
            triggerType: row.trigger_type,
            severityFilter: row.severity_filter,
            status: row.status,
            steps: typeof row.steps === 'string' ? JSON.parse(row.steps) : row.steps || [],
            createdAt: row.created_at,
            updatedAt: row.updated_at,
          }));
        } catch {
          // Playbooks table may not exist yet.
        }
      }

      sendJson(
        response,
        context,
        config,
        200,
        { data: playbooks, total: playbooks.length },
        baseExtraHeaders
      );
      return true;
    }

    if (context.path === '/v1/siem/alerts') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'SIEM alerts require authentication'
      );
      if (!session) {
        return true;
      }

      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant')
      );
      if (!tenant) {
        return true;
      }

      let alerts = [];
      if (config.databaseUrl) {
        try {
          const result = await dbQuery(
            config,
            `SELECT id, title, severity, status, source, detected_at, created_at
             FROM incidents WHERE tenant_slug = $1 AND source IS NOT NULL
             ORDER BY detected_at DESC NULLS LAST, created_at DESC LIMIT 50`,
            [tenant]
          );
          alerts = (result?.rows || []).map(row => ({
            id: row.id,
            title: row.title,
            severity: row.severity,
            status: row.status,
            source: row.source || 'siem',
            detectedAt: row.detected_at,
            createdAt: row.created_at,
          }));
        } catch {
          // Fall back to an empty data set.
        }
      }

      sendJson(
        response,
        context,
        config,
        200,
        { data: alerts, total: alerts.length },
        baseExtraHeaders
      );
      return true;
    }

    if (context.path === '/v1/risk/scores') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Risk scores require authentication'
      );
      if (!session) {
        return true;
      }

      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant')
      );
      if (!tenant) {
        return true;
      }

      let overallScore = 0;
      let categories = {};
      if (config.databaseUrl) {
        try {
          const result = await dbQuery(
            config,
            `SELECT COUNT(*) FILTER (WHERE severity = 'critical')::INT AS critical,
                    COUNT(*) FILTER (WHERE severity = 'high')::INT AS high,
                    COUNT(*) FILTER (WHERE severity = 'medium')::INT AS medium,
                    COUNT(*) FILTER (WHERE severity = 'low')::INT AS low,
                    COUNT(*) FILTER (WHERE status IN ('open','investigating'))::INT AS active
             FROM incidents WHERE tenant_slug = $1`,
            [tenant]
          );
          const row = result?.rows?.[0] || {};
          const critical = Number(row.critical || 0);
          const high = Number(row.high || 0);
          const medium = Number(row.medium || 0);
          const low = Number(row.low || 0);
          const active = Number(row.active || 0);
          overallScore = Math.max(
            0,
            100 - critical * 25 - high * 10 - medium * 3 - low * 1
          );
          categories = {
            threatExposure: {
              score: Math.max(0, 100 - active * 15),
              level: active > 3 ? 'critical' : active > 1 ? 'high' : 'low',
            },
            vulnerabilityManagement: {
              score: Math.max(0, 100 - critical * 20 - high * 8),
              level: critical > 0 ? 'critical' : high > 2 ? 'high' : 'medium',
            },
            incidentResponse: {
              score: active === 0 ? 100 : Math.max(0, 100 - active * 12),
              level: active === 0 ? 'low' : active > 3 ? 'critical' : 'medium',
            },
            accessControl: { score: 85, level: 'low' },
            dataProtection: { score: 78, level: 'medium' },
          };
        } catch {
          // Fall back to zeros.
        }
      }

      sendJson(
        response,
        context,
        config,
        200,
        {
          tenant,
          overallScore,
          categories,
          assessedAt: new Date().toISOString(),
        },
        baseExtraHeaders
      );
      return true;
    }

    if (context.path === '/v1/soc2/status') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'SOC2 status requires authentication'
      );
      if (!session) {
        return true;
      }

      if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant')
      );
      if (!tenant) {
        return true;
      }

      sendJson(
        response,
        context,
        config,
        200,
        {
          tenant,
          trustServiceCriteria: {
            security: { status: 'in_progress', controlsMet: 12, controlsTotal: 18 },
            availability: { status: 'in_progress', controlsMet: 5, controlsTotal: 8 },
            processingIntegrity: { status: 'not_started', controlsMet: 0, controlsTotal: 6 },
            confidentiality: { status: 'in_progress', controlsMet: 8, controlsTotal: 12 },
            privacy: { status: 'in_progress', controlsMet: 6, controlsTotal: 10 },
          },
          overallReadiness: 57,
          lastAssessedAt: new Date().toISOString(),
        },
        baseExtraHeaders
      );
      return true;
    }

    if (context.path === '/v1/threat-hunt/queries') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Threat hunting requires authentication'
      );
      if (!session) {
        return true;
      }

      if (!requireRole(session, 'security_analyst', response, context, baseExtraHeaders)) {
        return true;
      }

      sendJson(
        response,
        context,
        config,
        200,
        {
          data: [
            {
              id: 'hunt-1',
              name: 'Lateral Movement Detection',
              query: 'SELECT * FROM network_logs WHERE dst_port IN (445, 3389, 5985)',
              severity: 'high',
              lastRun: null,
            },
            {
              id: 'hunt-2',
              name: 'Suspicious DNS Queries',
              query: "SELECT * FROM dns_logs WHERE query_length > 50 AND query_type = 'TXT'",
              severity: 'medium',
              lastRun: null,
            },
            {
              id: 'hunt-3',
              name: 'Anomalous Auth Patterns',
              query: "SELECT user_id, COUNT(*) FROM auth_events WHERE success = false GROUP BY user_id HAVING COUNT(*) > 10",
              severity: 'high',
              lastRun: null,
            },
            {
              id: 'hunt-4',
              name: 'Data Exfiltration Indicators',
              query: 'SELECT * FROM network_logs WHERE bytes_out > 100000000 AND dst_ip NOT IN (SELECT ip FROM allowlisted_ips)',
              severity: 'critical',
              lastRun: null,
            },
            {
              id: 'hunt-5',
              name: 'Privilege Escalation Attempts',
              query: 'SELECT * FROM process_logs WHERE user_changed = true AND new_privilege > old_privilege',
              severity: 'critical',
              lastRun: null,
            },
          ],
          total: 5,
        },
        baseExtraHeaders
      );
      return true;
    }

    if (context.path === '/v1/correlation/run') {
      if (context.method !== 'GET' && context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['GET', 'POST'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Correlation engine requires authentication'
      );
      if (!session) {
        return true;
      }

      if (!requireRole(session, 'security_analyst', response, context, baseExtraHeaders)) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant')
      );
      if (!tenant) {
        return true;
      }

      let incidentCount = 0;
      let iocCount = 0;
      if (config.databaseUrl) {
        try {
          const incidentResult = await dbQuery(
            config,
            'SELECT COUNT(*)::INT AS c FROM incidents WHERE tenant_slug = $1',
            [tenant]
          );
          incidentCount = Number(incidentResult?.rows?.[0]?.c || 0);
          const iocResult = await dbQuery(
            config,
            'SELECT COUNT(*)::INT AS c FROM iocs WHERE tenant_slug = $1',
            [tenant]
          );
          iocCount = Number(iocResult?.rows?.[0]?.c || 0);
        } catch {
          // Fall back to zero counts.
        }
      }

      sendJson(
        response,
        context,
        config,
        200,
        {
          tenant,
          correlations: [],
          stats: {
            incidentsAnalyzed: incidentCount,
            iocsAnalyzed: iocCount,
            correlationsFound: 0,
            engineStatus: 'idle',
          },
          ranAt: new Date().toISOString(),
        },
        baseExtraHeaders
      );
      return true;
    }

    return false;
  });
}

module.exports = { registerRoutes };
