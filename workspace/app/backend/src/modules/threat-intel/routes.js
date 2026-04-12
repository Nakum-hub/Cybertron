const routes = [
  { method: 'POST', path: '/v1/threat-intel/cve/sync' },
  { method: 'GET', path: '/v1/threat-intel/cve/feed' },
  { method: 'POST', path: '/v1/threat-intel/cve/:cveId/summarize' },
  { method: 'GET', path: '/v1/threat-intel/dashboard' },
  { method: 'GET', path: '/v1/threat-intel/ai/runtime' },
  // MITRE ATT&CK
  { method: 'GET', path: '/v1/threat-intel/mitre/techniques' },
  { method: 'GET', path: '/v1/threat-intel/mitre/heatmap' },
  { method: 'GET', path: '/v1/threat-intel/mitre/incidents/:incidentId' },
  { method: 'POST', path: '/v1/threat-intel/mitre/incidents/:incidentId' },
  { method: 'DELETE', path: '/v1/threat-intel/mitre/mappings/:mappingId' },
  // Playbooks
  { method: 'GET', path: '/v1/threat-intel/playbooks' },
  { method: 'POST', path: '/v1/threat-intel/playbooks' },
  { method: 'GET', path: '/v1/threat-intel/playbooks/:id' },
  { method: 'PUT', path: '/v1/threat-intel/playbooks/:id' },
  { method: 'POST', path: '/v1/threat-intel/playbooks/:id/steps' },
  { method: 'POST', path: '/v1/threat-intel/playbooks/:id/execute' },
  { method: 'GET', path: '/v1/threat-intel/playbooks/executions' },
  { method: 'PUT', path: '/v1/threat-intel/playbooks/executions/:execId/steps/:stepId' },
  // SIEM Alerts
  { method: 'POST', path: '/v1/threat-intel/siem/upload' },
  { method: 'GET', path: '/v1/threat-intel/siem/alerts' },
  { method: 'POST', path: '/v1/threat-intel/siem/alerts' },
  { method: 'GET', path: '/v1/threat-intel/siem/alerts/stats' },
  { method: 'POST', path: '/v1/threat-intel/siem/alerts/:alertId/correlate' },
  // Alert Lifecycle
  { method: 'PATCH', path: '/v1/threat-intel/siem/alerts/:alertId/status' },
  { method: 'PATCH', path: '/v1/threat-intel/siem/alerts/:alertId/assign' },
  { method: 'POST', path: '/v1/threat-intel/siem/alerts/:alertId/escalate' },
  { method: 'GET', path: '/v1/threat-intel/siem/correlation-rules' },
  { method: 'POST', path: '/v1/threat-intel/siem/correlation-rules' },
  { method: 'PUT', path: '/v1/threat-intel/siem/correlation-rules/:ruleId' },
  // Connector Sync
  { method: 'POST', path: '/v1/threat-intel/siem/sync-connectors' },
  // Correlation Engine
  { method: 'POST', path: '/v1/threat-intel/siem/correlate-all' },
  // SIEM Export
  { method: 'GET', path: '/v1/threat-intel/siem/export' },
  // SOC Operations
  { method: 'POST', path: '/v1/threat-intel/siem/alerts/bulk-status' },
  { method: 'GET', path: '/v1/threat-intel/siem/alerts/sla-metrics' },
  { method: 'GET', path: '/v1/threat-intel/siem/alerts/:alertId/triage-suggestion' },
  { method: 'PATCH', path: '/v1/threat-intel/siem/alerts/:alertId/notes' },
  { method: 'GET', path: '/v1/threat-intel/siem/attack-map' },
  { method: 'GET', path: '/v1/threat-intel/analysts' },
  // Threat Hunting
  { method: 'GET', path: '/v1/threat-intel/hunts' },
  { method: 'POST', path: '/v1/threat-intel/hunts' },
  { method: 'PUT', path: '/v1/threat-intel/hunts/:id' },
  { method: 'DELETE', path: '/v1/threat-intel/hunts/:id' },
  { method: 'POST', path: '/v1/threat-intel/hunts/:id/execute' },
];

function registerRoutes(routerContext) {
  const register = routerContext?.register;
  if (typeof register !== 'function') {
    throw new Error('threat-intel routes require routerContext.register(handler)');
  }

  const deps = routerContext.deps || {};
  const {
    config,
    sendJson,
    sendError,
    sendMethodNotAllowed,
    requireDatabaseConfigured,
    requireSession,
    resolveTenantForRequest,
    requireProductAccess,
    requireFeatureFlagEnabled,
    isTenantFeatureEnabled,
    parseMultipartForm,
    sniffMimeType,
    enforceUploadPolicy,
    allowedSiemLogMimeTypes,
    parseSiemLogJsonBuffer,
    probeLlmRuntime,
    syncCveFeed,
    log,
    appendAuditLog,
    actorMetaFromContext,
    meterUsage,
    handleServiceFailure,
    toSafeInteger,
    parseJsonBody,
    validateBodyShape,
    listTenantCveFeed,
    getCveRecord,
    summarizeCveWithAi,
    saveCveSummary,
    getThreatDashboard,
    // MITRE ATT&CK
    listMitreTechniques,
    listIncidentMitreMappings,
    addIncidentMitreMapping,
    removeIncidentMitreMapping,
    getMitreHeatmap,
    // Playbooks
    listPlaybooks,
    getPlaybookWithSteps,
    createPlaybook,
    updatePlaybook,
    addPlaybookStep,
    executePlaybook,
    listPlaybookExecutions,
    updatePlaybookStepResult,
    getExecutionStepResults,
    // SIEM
    listSiemAlerts,
    ingestSiemAlert,
    correlateAlertToIncident,
    getSiemAlertStats,
    updateAlertStatus,
    assignAlert,
    escalateAlertToIncident,
    bulkUpdateAlertStatus,
    getAlertSlaMetrics,
    getAlertTriageSuggestion,
    getAttackMapData,
    updateAlertNotes,
    listCorrelationRules,
    createCorrelationRule,
    updateCorrelationRule,
    // Threat Hunting
    listThreatHuntQueries,
    createThreatHuntQuery,
    updateThreatHuntQuery,
    deleteThreatHuntQuery,
    executeThreatHuntQuery,
    // Real-time Notifications
    notifyAlertIngested,
    notifyPlaybookExecuted,
    notifyIncidentCreated,
    // Connector Sync
    fetchConnectorIncidents,
    // Correlation Engine
    runCorrelationEngine,
    // Analyst List
    listTenantAnalysts,
  } = deps;
  const getExecutionStepResultsHandler =
    typeof getExecutionStepResults === 'function'
      ? getExecutionStepResults
      : require('../../playbook-service').getExecutionStepResults;

  // --- Helper: standard auth chain for threat-command product ---
  async function threatAuthChain(context, response, baseExtraHeaders, session, minRole) {
    const tenant = await resolveTenantForRequest(
      context,
      response,
      baseExtraHeaders,
      session,
      context.url.searchParams.get('tenant'),
      { allowCrossTenantRoles: ['super_admin'] }
    );
    if (!tenant) {
      return null;
    }

    const product = await requireProductAccess(
      context,
      response,
      baseExtraHeaders,
      session,
      tenant,
      'threat-command',
      minRole
    );
    if (!product) {
      return null;
    }

    if (!(await requireFeatureFlagEnabled(
      context,
      response,
      baseExtraHeaders,
      tenant,
      'product_threat_intel_enabled'
    ))) {
      return null;
    }

    return { tenant, product };
  }

  // ============================
  // Original CVE Routes
  // ============================

  register(async ({ context, response, baseExtraHeaders }) => {
    if (context.path === '/v1/threat-intel/cve/sync') {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Threat intel sync requires authenticated session'
      );
      if (!session) {
        return true;
      }

      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'tenant_admin');
      if (!auth) {
        return true;
      }

      try {
        const syncResult = await syncCveFeed(config, log, auth.tenant, session.user.id);

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.cve_sync.executed',
          targetType: 'threat_intel',
          targetId: 'nvd',
          payload: syncResult,
        });

        await meterUsage(context, session, auth.tenant, auth.product.productKey, 'cve_sync', 1, {
          cveCount: syncResult.cveCount,
          notModified: syncResult.notModified,
        });

        sendJson(response, context, config, 200, syncResult, baseExtraHeaders);
      } catch (error) {
        try {
          await appendAuditLog(config, {
            ...actorMetaFromContext(context, session),
            tenantSlug: auth.tenant,
            action: 'threat_intel.cve_sync.failed',
            targetType: 'threat_intel',
            targetId: 'nvd',
            payload: {
              code: error?.code || 'unknown_sync_failure',
              message: error instanceof Error ? error.message : 'unknown sync failure',
            },
          });
        } catch {
          // Preserve primary sync failure response even if audit persistence fails.
        }
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/threat-intel/cve/feed') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Threat intel feed requires authenticated session'
      );
      if (!session) {
        return true;
      }

      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'executive_viewer');
      if (!auth) {
        return true;
      }

      try {
        const limit = toSafeInteger(context.url.searchParams.get('limit'), 50, 1, 200);
        const offset = toSafeInteger(context.url.searchParams.get('offset'), 0, 0, 50_000);
        const severity = context.url.searchParams.get('severity') || '';
        const feed = await listTenantCveFeed(config, auth.tenant, { limit, offset, severity });

        await meterUsage(context, session, auth.tenant, auth.product.productKey, 'cve_feed_view', 1, {
          limit,
          offset,
          severity,
          returnedCount: Array.isArray(feed?.data) ? feed.data.length : 0,
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.cve_feed.viewed',
          targetType: 'cve',
          targetId: 'feed',
          payload: { limit, offset, severity },
        });

        sendJson(response, context, config, 200, feed, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (/^\/v1\/threat-intel\/cve\/[^/]+\/summarize$/.test(context.path)) {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Threat intel summarization requires authenticated session'
      );
      if (!session) {
        return true;
      }

      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) {
        return true;
      }

      if (!(await requireFeatureFlagEnabled(
        context,
        response,
        baseExtraHeaders,
        auth.tenant,
        'llm_features_enabled',
        {
          message:
            'LLM features are disabled for this tenant. Enable llm_features_enabled to summarize CVEs.',
        }
      ))) {
        return true;
      }

      try {
        const cveId = decodeURIComponent(context.path.split('/')[4] || '').toUpperCase();
        const cve = await getCveRecord(config, cveId);
        const summary = await summarizeCveWithAi(
          config,
          log,
          {
            tenant: auth.tenant,
            cveId: cve.cveId,
            severity: cve.severity,
            cvssScore: cve.cvssScore,
            description: cve.description,
            publishedAt: cve.publishedAt,
            lastModifiedAt: cve.lastModifiedAt,
          },
          {
            requestId: context.requestId,
            tenantSlug: auth.tenant,
            actorId: session.user.id,
            actorEmail: session.user.email,
            ipAddress: context.clientIp || null,
            userAgent: context.userAgent || null,
          }
        );

        const saved = await saveCveSummary(config, {
          tenant: auth.tenant,
          cveId: cve.cveId,
          summaryText: summary.summaryText,
          model: summary.model,
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.cve_summarized',
          targetType: 'cve',
          targetId: cve.cveId,
          payload: {
            summaryId: saved.id,
            provider: summary.provider,
            model: summary.model,
          },
        });

        await meterUsage(context, session, auth.tenant, auth.product.productKey, 'cve_summarize', 1, {
          cveId: cve.cveId,
        });

        sendJson(
          response,
          context,
          config,
          201,
          {
            summary: saved,
            llm: {
              provider: summary.provider,
              model: summary.model,
              aiGenerated: summary.aiGenerated,
              groundingScore: summary.groundingScore,
              qualityGate: summary.qualityGate,
            },
          },
          baseExtraHeaders
        );
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/threat-intel/dashboard') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Threat dashboard requires authenticated session'
      );
      if (!session) {
        return true;
      }

      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'executive_viewer');
      if (!auth) {
        return true;
      }

      try {
        const days = toSafeInteger(context.url.searchParams.get('days'), 30, 1, 180);
        const dashboard = await getThreatDashboard(config, auth.tenant, { days });

        await meterUsage(context, session, auth.tenant, auth.product.productKey, 'threat_dashboard_view', 1, {
          days,
          trendPoints: Array.isArray(dashboard?.trend) ? dashboard.trend.length : 0,
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.dashboard.viewed',
          targetType: 'threat_dashboard',
          targetId: 'current',
          payload: { days },
        });

        sendJson(response, context, config, 200, dashboard, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ============================
    // MITRE ATT&CK Routes
    // ============================

    if (context.path === '/v1/threat-intel/mitre/techniques') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'MITRE techniques require authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'executive_viewer');
      if (!auth) {
        return true;
      }

      try {
        const tactic = context.url.searchParams.get('tactic') || undefined;
        const result = await listMitreTechniques(config, { tactic });
        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/threat-intel/mitre/heatmap') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'MITRE heatmap requires authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'executive_viewer');
      if (!auth) {
        return true;
      }

      try {
        const result = await getMitreHeatmap(config, auth.tenant);

        await meterUsage(context, session, auth.tenant, auth.product.productKey, 'mitre_heatmap_view', 1, {});

        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (/^\/v1\/threat-intel\/mitre\/incidents\/[0-9]+$/.test(context.path)) {
      const incidentId = context.path.split('/')[5];

      if (context.method === 'GET') {
        if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
          return true;
        }
        const session = await requireSession(context, response, baseExtraHeaders, 'MITRE mappings require authenticated session');
        if (!session) {
          return true;
        }
        const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'executive_viewer');
        if (!auth) {
          return true;
        }

        try {
          const result = await listIncidentMitreMappings(config, auth.tenant, incidentId);
          sendJson(response, context, config, 200, result, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      if (context.method === 'POST') {
        if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
          return true;
        }
        const session = await requireSession(context, response, baseExtraHeaders, 'MITRE mapping creation requires authenticated session');
        if (!session) {
          return true;
        }
        const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
        if (!auth) {
          return true;
        }

        const payload = await parseJsonBody(context, response, baseExtraHeaders);
        if (!payload) {
          return true;
        }
        if (!validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['techniqueId'],
          optional: ['confidence', 'notes'],
        })) {
          return true;
        }

        try {
          const mapping = await addIncidentMitreMapping(config, {
            tenant: auth.tenant,
            incidentId,
            techniqueId: payload.techniqueId,
            confidence: payload.confidence,
            notes: payload.notes,
            createdBy: session.user.id,
          });

          await appendAuditLog(config, {
            ...actorMetaFromContext(context, session),
            tenantSlug: auth.tenant,
            action: 'threat_intel.mitre_mapping.created',
            targetType: 'incident',
            targetId: String(incidentId),
            payload: { techniqueId: payload.techniqueId, mappingId: mapping?.id },
          });

          await meterUsage(context, session, auth.tenant, auth.product.productKey, 'mitre_mapping_create', 1, {});

          sendJson(response, context, config, 201, mapping, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      sendMethodNotAllowed(response, context, config, ['GET', 'POST'], baseExtraHeaders);
      return true;
    }

    if (/^\/v1\/threat-intel\/mitre\/mappings\/[0-9]+$/.test(context.path)) {
      if (context.method !== 'DELETE') {
        sendMethodNotAllowed(response, context, config, ['DELETE'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'MITRE mapping removal requires authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) {
        return true;
      }

      try {
        const mappingId = context.path.split('/')[5];
        const removed = await removeIncidentMitreMapping(config, auth.tenant, mappingId);

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.mitre_mapping.deleted',
          targetType: 'mitre_mapping',
          targetId: String(mappingId),
          payload: { removed },
        });

        sendJson(response, context, config, 200, { removed }, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ============================
    // Playbook Routes
    // ============================

    if (context.path === '/v1/threat-intel/playbooks/executions') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'Playbook executions require authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'executive_viewer');
      if (!auth) {
        return true;
      }

      try {
        const limit = toSafeInteger(context.url.searchParams.get('limit'), 50, 1, 200);
        const offset = toSafeInteger(context.url.searchParams.get('offset'), 0, 0, 50_000);
        const playbookId = context.url.searchParams.get('playbookId') || undefined;
        const incidentId = context.url.searchParams.get('incidentId') || undefined;
        const status = context.url.searchParams.get('status') || undefined;

        const result = await listPlaybookExecutions(config, auth.tenant, { playbookId, incidentId, status, limit, offset });

        await meterUsage(context, session, auth.tenant, auth.product.productKey, 'playbook_executions_view', 1, {});

        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (/^\/v1\/threat-intel\/playbooks\/executions\/[0-9]+\/steps\/[0-9]+$/.test(context.path)) {
      if (context.method !== 'PUT') {
        sendMethodNotAllowed(response, context, config, ['PUT'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'Playbook step update requires authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }
      if (!validateBodyShape(context, response, baseExtraHeaders, payload, {
        required: ['status'],
        optional: ['notes'],
      })) {
        return true;
      }

      try {
        const parts = context.path.split('/');
        const execId = parts[5];
        const stepId = parts[7];

        const result = await updatePlaybookStepResult(config, auth.tenant, execId, stepId, {
          status: payload.status,
          notes: payload.notes,
          completedBy: session.user.id,
        });

        if (!result) {
          sendError(response, context, config, 404, 'not_found', 'Step result not found', null, baseExtraHeaders);
          return true;
        }

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.playbook_step.updated',
          targetType: 'playbook_step_result',
          targetId: String(result.id),
          payload: { status: payload.status, previousStatus: result.previousStatus || null, executionId: execId, stepId },
        });

        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // GET /v1/threat-intel/playbooks/executions/:execId/steps — list step results for an execution
    if (/^\/v1\/threat-intel\/playbooks\/executions\/[0-9]+\/steps$/.test(context.path)) {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'Execution step results require authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'executive_viewer');
      if (!auth) {
        return true;
      }

      try {
        const execId = context.path.split('/')[5];
        const steps = await getExecutionStepResultsHandler(config, auth.tenant, execId);
        sendJson(response, context, config, 200, { data: steps }, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/threat-intel/playbooks') {
      if (context.method === 'GET') {
        if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
          return true;
        }
        const session = await requireSession(context, response, baseExtraHeaders, 'Playbooks require authenticated session');
        if (!session) {
          return true;
        }
        const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'executive_viewer');
        if (!auth) {
          return true;
        }

        try {
          const limit = toSafeInteger(context.url.searchParams.get('limit'), 50, 1, 200);
          const offset = toSafeInteger(context.url.searchParams.get('offset'), 0, 0, 50_000);
          const category = context.url.searchParams.get('category') || undefined;

          const result = await listPlaybooks(config, auth.tenant, { limit, offset, category });

          await meterUsage(context, session, auth.tenant, auth.product.productKey, 'playbooks_view', 1, {});

          sendJson(response, context, config, 200, result, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      if (context.method === 'POST') {
        if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
          return true;
        }
        const session = await requireSession(context, response, baseExtraHeaders, 'Playbook creation requires authenticated session');
        if (!session) {
          return true;
        }
        const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
        if (!auth) {
          return true;
        }

        const payload = await parseJsonBody(context, response, baseExtraHeaders);
        if (!payload) {
          return true;
        }
        if (!validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['name'],
          optional: ['description', 'severityFilter', 'category'],
        })) {
          return true;
        }

        try {
          const playbook = await createPlaybook(config, {
            tenant: auth.tenant,
            name: payload.name,
            description: payload.description,
            severityFilter: payload.severityFilter,
            category: payload.category,
            createdBy: session.user.id,
          });

          await appendAuditLog(config, {
            ...actorMetaFromContext(context, session),
            tenantSlug: auth.tenant,
            action: 'threat_intel.playbook.created',
            targetType: 'playbook',
            targetId: String(playbook?.id),
            payload: { name: payload.name },
          });

          await meterUsage(context, session, auth.tenant, auth.product.productKey, 'playbook_create', 1, {});

          sendJson(response, context, config, 201, playbook, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      sendMethodNotAllowed(response, context, config, ['GET', 'POST'], baseExtraHeaders);
      return true;
    }

    if (/^\/v1\/threat-intel\/playbooks\/[0-9]+\/steps$/.test(context.path)) {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'Playbook step creation requires authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }
      if (!validateBodyShape(context, response, baseExtraHeaders, payload, {
        required: ['title'],
        optional: ['description', 'actionType', 'assignedRole', 'timeoutMinutes', 'stepOrder'],
      })) {
        return true;
      }

      try {
        const playbookId = context.path.split('/')[4];
        const step = await addPlaybookStep(config, playbookId, {
          title: payload.title,
          description: payload.description,
          actionType: payload.actionType,
          assignedRole: payload.assignedRole,
          timeoutMinutes: payload.timeoutMinutes,
          stepOrder: payload.stepOrder,
        }, auth.tenant);

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.playbook_step.created',
          targetType: 'playbook_step',
          targetId: String(step?.id),
          payload: { playbookId, title: payload.title },
        });

        sendJson(response, context, config, 201, step, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (/^\/v1\/threat-intel\/playbooks\/[0-9]+\/execute$/.test(context.path)) {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'Playbook execution requires authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) {
        return true;
      }

      try {
        const playbookId = context.path.split('/')[4];
        const payload = await parseJsonBody(context, response, baseExtraHeaders);
        const incidentId = payload?.incidentId || null;

        const execution = await executePlaybook(config, {
          tenant: auth.tenant,
          playbookId,
          incidentId,
          startedBy: session.user.id,
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.playbook.executed',
          targetType: 'playbook_execution',
          targetId: String(execution?.id),
          payload: { playbookId, incidentId },
        });

        await meterUsage(context, session, auth.tenant, auth.product.productKey, 'playbook_execute', 1, {});

        notifyPlaybookExecuted(auth.tenant, execution);

        sendJson(response, context, config, 201, execution, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (/^\/v1\/threat-intel\/playbooks\/[0-9]+$/.test(context.path)) {
      const playbookId = context.path.split('/')[4];

      if (context.method === 'GET') {
        if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
          return true;
        }
        const session = await requireSession(context, response, baseExtraHeaders, 'Playbook detail requires authenticated session');
        if (!session) {
          return true;
        }
        const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'executive_viewer');
        if (!auth) {
          return true;
        }

        try {
          const playbook = await getPlaybookWithSteps(config, auth.tenant, playbookId);
          if (!playbook) {
            sendError(response, context, config, 404, 'not_found', 'Playbook not found', null, baseExtraHeaders);
            return true;
          }
          sendJson(response, context, config, 200, playbook, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      if (context.method === 'PUT') {
        if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
          return true;
        }
        const session = await requireSession(context, response, baseExtraHeaders, 'Playbook update requires authenticated session');
        if (!session) {
          return true;
        }
        const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
        if (!auth) {
          return true;
        }

        const payload = await parseJsonBody(context, response, baseExtraHeaders);
        if (!payload) {
          return true;
        }

        if (!validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: [],
          optional: ['name', 'description', 'severityFilter', 'category', 'isActive'],
        })) {
          return true;
        }

        try {
          const updated = await updatePlaybook(config, auth.tenant, playbookId, {
            name: payload.name,
            description: payload.description,
            severityFilter: payload.severityFilter,
            category: payload.category,
            isActive: payload.isActive,
          });

          if (!updated) {
            sendError(response, context, config, 404, 'not_found', 'Playbook not found', null, baseExtraHeaders);
            return true;
          }

          await appendAuditLog(config, {
            ...actorMetaFromContext(context, session),
            tenantSlug: auth.tenant,
            action: 'threat_intel.playbook.updated',
            targetType: 'playbook',
            targetId: String(playbookId),
            payload: { fields: Object.keys(payload) },
          });

          sendJson(response, context, config, 200, updated, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      sendMethodNotAllowed(response, context, config, ['GET', 'PUT'], baseExtraHeaders);
      return true;
    }

    // ============================
    // SIEM Alert Routes
    // ============================

    if (context.path === '/v1/threat-intel/siem/alerts/stats') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'SIEM stats require authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'executive_viewer');
      if (!auth) {
        return true;
      }

      try {
        const stats = await getSiemAlertStats(config, auth.tenant);
        sendJson(response, context, config, 200, { stats: stats || {} }, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/threat-intel/ai/runtime') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Threat AI runtime status requires authenticated session'
      );
      if (!session) {
        return true;
      }

      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) {
        return true;
      }

      try {
        const llmFeaturesEnabled = typeof isTenantFeatureEnabled === 'function'
          ? await isTenantFeatureEnabled(auth.tenant, 'llm_features_enabled')
          : false;
        const runtime = typeof probeLlmRuntime === 'function'
          ? await probeLlmRuntime(config)
          : {
              provider: 'none',
              deployment: 'fallback_only',
              configured: false,
              reachable: false,
              model: null,
              endpoint: '',
              checkedAt: new Date().toISOString(),
              latencyMs: null,
              availableModels: [],
              sshTunnelSuggested: false,
              reason: 'LLM runtime probe is unavailable.',
            };

        await meterUsage(context, session, auth.tenant, auth.product.productKey, 'threat_ai_runtime_view', 1, {
          provider: runtime.provider,
          configured: runtime.configured,
          reachable: runtime.reachable,
          llmFeaturesEnabled,
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.ai_runtime.viewed',
          targetType: 'llm_runtime',
          targetId: runtime.provider || 'none',
          payload: {
            deployment: runtime.deployment,
            configured: runtime.configured,
            reachable: runtime.reachable,
            llmFeaturesEnabled,
          },
        });

        sendJson(response, context, config, 200, {
          ...runtime,
          featureFlags: {
            llmFeaturesEnabled,
          },
        }, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/threat-intel/siem/upload') {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'SIEM file upload requires authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) {
        return true;
      }

      try {
        const parsed = await parseMultipartForm(context.request, {
          maxFileSize: config.aiUploadMaxBytes,
        });
        const detectedMime = sniffMimeType(parsed.file.buffer);
        const policy = enforceUploadPolicy({
          fileName: parsed.file.fileName,
          clientMimeType: parsed.file.mimeType,
          sniffedMimeType: detectedMime,
          allowedMimeTypes: allowedSiemLogMimeTypes,
          maxBytes: config.aiUploadMaxBytes,
          sizeBytes: parsed.file.sizeBytes,
        });

        if (!['application/json', 'text/plain'].includes(policy.mimeType)) {
          sendError(
            response,
            context,
            config,
            415,
            'invalid_siem_log_mime',
            'SOC log ingestion accepts JSON or JSON Lines uploads only.',
            null,
            baseExtraHeaders
          );
          return true;
        }

        const runCorrelation = String(
          parsed.fields.runCorrelation || context.url.searchParams.get('runCorrelation') || ''
        ).toLowerCase() === 'true';
        const sourceHint = String(parsed.fields.source || parsed.file.fileName || '').trim();
        const normalized = parseSiemLogJsonBuffer(parsed.file.buffer, { defaultSource: sourceHint });

        let ingestedAlerts = 0;
        const sampleAlerts = [];
        const errors = [];

        for (const record of normalized.records) {
          try {
            const alert = await ingestSiemAlert(config, {
              tenant: auth.tenant,
              source: record.source,
              alertId: record.alertId,
              ruleName: record.ruleName,
              severity: record.severity,
              category: record.category,
              rawPayload: record.rawPayload,
              sourceIp: record.sourceIp,
              destIp: record.destIp,
              hostname: record.hostname,
              eventTime: record.eventTime,
            });

            if (alert) {
              ingestedAlerts += 1;
              if (sampleAlerts.length < 10) {
                sampleAlerts.push(alert);
              }
              if (ingestedAlerts <= 100) {
                notifyAlertIngested(auth.tenant, alert);
              }
            }
          } catch (ingestError) {
            errors.push({
              ruleName: record.ruleName,
              source: record.source,
              error: ingestError instanceof Error ? ingestError.message : 'ingestion failed',
            });
          }
        }

        let correlationRun = null;
        if (runCorrelation) {
          correlationRun = await runCorrelationEngine(config, auth.tenant, log, {
            notifyIncidentCreated,
            executePlaybook,
          });
        }

        await meterUsage(
          context,
          session,
          auth.tenant,
          auth.product.productKey,
          'siem_file_upload',
          Math.max(1, normalized.count),
          {
            uploadedRecords: normalized.count,
            ingestedAlerts,
            runCorrelation,
          }
        );

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.siem.uploaded',
          targetType: 'siem_upload',
          targetId: null,
          payload: {
            fileName: parsed.file.fileName,
            mimeType: policy.mimeType,
            uploadedRecords: normalized.count,
            ingestedAlerts,
            errorCount: errors.length,
            runCorrelation,
            correlationCount: correlationRun?.correlations?.length || 0,
          },
        });

        sendJson(
          response,
          context,
          config,
          201,
          {
            uploadedRecords: normalized.count,
            ingestedAlerts,
            errorCount: errors.length,
            sampleAlerts,
            errors: errors.slice(0, 20),
            correlationRun,
            message: `Uploaded ${normalized.count} records and ingested ${ingestedAlerts} SIEM alerts.`,
          },
          baseExtraHeaders
        );
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/threat-intel/siem/alerts') {
      if (context.method === 'GET') {
        if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
          return true;
        }
        const session = await requireSession(context, response, baseExtraHeaders, 'SIEM alerts require authenticated session');
        if (!session) {
          return true;
        }
        const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'executive_viewer');
        if (!auth) {
          return true;
        }

        try {
          const limit = toSafeInteger(context.url.searchParams.get('limit'), 50, 1, 200);
          const offset = toSafeInteger(context.url.searchParams.get('offset'), 0, 0, 50_000);
          const severity = context.url.searchParams.get('severity') || undefined;
          const source = context.url.searchParams.get('source') || undefined;
          const correlated = context.url.searchParams.get('correlated');
          const status = context.url.searchParams.get('status') || undefined;
          const assignedTo = context.url.searchParams.get('assignedTo') || undefined;
          const search = context.url.searchParams.get('search') || undefined;

          const result = await listSiemAlerts(config, auth.tenant, {
            limit,
            offset,
            severity,
            source,
            correlated: correlated !== null && correlated !== undefined ? correlated : undefined,
            status,
            assignedTo,
            search,
          });

          await meterUsage(context, session, auth.tenant, auth.product.productKey, 'siem_alerts_view', 1, {});

          sendJson(response, context, config, 200, result, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      if (context.method === 'POST') {
        if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
          return true;
        }
        const session = await requireSession(context, response, baseExtraHeaders, 'SIEM alert ingestion requires authenticated session');
        if (!session) {
          return true;
        }
        const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
        if (!auth) {
          return true;
        }

        const payload = await parseJsonBody(context, response, baseExtraHeaders);
        if (!payload) {
          return true;
        }
        if (!validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['source'],
          optional: ['alertId', 'ruleName', 'severity', 'category', 'rawPayload', 'sourceIp', 'destIp', 'hostname', 'eventTime'],
        })) {
          return true;
        }

        try {
          const alert = await ingestSiemAlert(config, {
            tenant: auth.tenant,
            source: payload.source,
            alertId: payload.alertId,
            ruleName: payload.ruleName,
            severity: payload.severity,
            category: payload.category,
            rawPayload: payload.rawPayload,
            sourceIp: payload.sourceIp,
            destIp: payload.destIp,
            hostname: payload.hostname,
            eventTime: payload.eventTime,
          });

          await meterUsage(context, session, auth.tenant, auth.product.productKey, 'siem_alert_ingest', 1, {});

          notifyAlertIngested(auth.tenant, alert);

          sendJson(response, context, config, 201, alert, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      sendMethodNotAllowed(response, context, config, ['GET', 'POST'], baseExtraHeaders);
      return true;
    }

    if (/^\/v1\/threat-intel\/siem\/alerts\/[0-9]+\/correlate$/.test(context.path)) {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'Alert correlation requires authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }
      if (!validateBodyShape(context, response, baseExtraHeaders, payload, {
        required: ['incidentId'],
        optional: [],
      })) {
        return true;
      }

      try {
        const alertId = context.path.split('/')[5];
        const correlated = await correlateAlertToIncident(config, auth.tenant, alertId, payload.incidentId);

        if (!correlated) {
          sendError(response, context, config, 404, 'not_found', 'Alert not found', null, baseExtraHeaders);
          return true;
        }

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.siem_alert.correlated',
          targetType: 'siem_alert',
          targetId: String(alertId),
          payload: { incidentId: payload.incidentId },
        });

        sendJson(response, context, config, 200, correlated, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ============================
    // Alert Lifecycle Routes
    // ============================

    // PATCH /v1/threat-intel/siem/alerts/:alertId/status
    const statusMatch = context.path.match(/^\/v1\/threat-intel\/siem\/alerts\/(\d+)\/status$/);
    if (statusMatch) {
      if (context.method !== 'PATCH') {
        sendMethodNotAllowed(response, context, config, ['PATCH'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Alert status update requires authenticated session');
      if (!session) return true;
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) return true;

      const payload = await parseJsonBody(context, response, baseExtraHeaders, 1024);
      if (!payload) return true;
      if (!payload.status) {
        sendError(response, context, config, 400, 'missing_status', 'status field is required', null, baseExtraHeaders);
        return true;
      }

      try {
        const result = await updateAlertStatus(config, auth.tenant, statusMatch[1], {
          status: payload.status,
          userId: session?.user?.id,
          notes: payload.notes,
        });
        if (!result) {
          sendError(response, context, config, 404, 'not_found', 'Alert not found', null, baseExtraHeaders);
          return true;
        }

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.siem_alert.status_changed',
          targetType: 'siem_alert',
          targetId: statusMatch[1],
          payload: { status: payload.status },
        });

        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // PATCH /v1/threat-intel/siem/alerts/:alertId/assign
    const assignMatch = context.path.match(/^\/v1\/threat-intel\/siem\/alerts\/(\d+)\/assign$/);
    if (assignMatch) {
      if (context.method !== 'PATCH') {
        sendMethodNotAllowed(response, context, config, ['PATCH'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Alert assignment requires authenticated session');
      if (!session) return true;
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) return true;

      const payload = await parseJsonBody(context, response, baseExtraHeaders, 512);
      if (!payload) return true;

      try {
        const result = await assignAlert(config, auth.tenant, assignMatch[1], {
          assignedTo: payload.assignedTo || null,
          userId: session?.user?.id,
        });
        if (!result) {
          sendError(response, context, config, 404, 'not_found', 'Alert not found', null, baseExtraHeaders);
          return true;
        }

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.siem_alert.assigned',
          targetType: 'siem_alert',
          targetId: assignMatch[1],
          payload: { assignedTo: payload.assignedTo },
        });

        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // POST /v1/threat-intel/siem/alerts/:alertId/escalate
    const escalateMatch = context.path.match(/^\/v1\/threat-intel\/siem\/alerts\/(\d+)\/escalate$/);
    if (escalateMatch) {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Alert escalation requires authenticated session');
      if (!session) return true;
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) return true;

      const payload = await parseJsonBody(context, response, baseExtraHeaders, 1024);
      if (!payload) return true;

      try {
        const result = await escalateAlertToIncident(config, auth.tenant, escalateMatch[1], {
          userId: session?.user?.id,
          title: payload.title,
          severity: payload.severity,
          priority: payload.priority,
        });
        if (!result) {
          sendError(response, context, config, 404, 'not_found', 'Alert not found or escalation failed', null, baseExtraHeaders);
          return true;
        }

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.siem_alert.escalated',
          targetType: 'siem_alert',
          targetId: escalateMatch[1],
          payload: { incidentId: result.incidentId, title: result.title },
        });

        sendJson(response, context, config, 201, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/threat-intel/siem/correlation-rules') {
      if (context.method === 'GET') {
        if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
          return true;
        }
        const session = await requireSession(context, response, baseExtraHeaders, 'Correlation rules require authenticated session');
        if (!session) {
          return true;
        }
        const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'executive_viewer');
        if (!auth) {
          return true;
        }

        try {
          const result = await listCorrelationRules(config, auth.tenant);
          sendJson(response, context, config, 200, result, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      if (context.method === 'POST') {
        if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
          return true;
        }
        const session = await requireSession(context, response, baseExtraHeaders, 'Correlation rule creation requires authenticated session');
        if (!session) {
          return true;
        }
        const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
        if (!auth) {
          return true;
        }

        const payload = await parseJsonBody(context, response, baseExtraHeaders);
        if (!payload) {
          return true;
        }
        if (!validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['name'],
          optional: ['description', 'ruleType', 'conditions', 'severityOutput'],
        })) {
          return true;
        }

        try {
          const rule = await createCorrelationRule(config, {
            tenant: auth.tenant,
            name: payload.name,
            description: payload.description,
            ruleType: payload.ruleType,
            conditions: payload.conditions,
            severityOutput: payload.severityOutput,
            createdBy: session.user.id,
          });

          await appendAuditLog(config, {
            ...actorMetaFromContext(context, session),
            tenantSlug: auth.tenant,
            action: 'threat_intel.correlation_rule.created',
            targetType: 'correlation_rule',
            targetId: String(rule?.id),
            payload: { name: payload.name, ruleType: payload.ruleType },
          });

          sendJson(response, context, config, 201, rule, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      sendMethodNotAllowed(response, context, config, ['GET', 'POST'], baseExtraHeaders);
      return true;
    }

    if (/^\/v1\/threat-intel\/siem\/correlation-rules\/[0-9]+$/.test(context.path)) {
      if (context.method !== 'PUT') {
        sendMethodNotAllowed(response, context, config, ['PUT'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'Correlation rule update requires authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }

      try {
        const ruleId = context.path.split('/')[5];
        const updated = await updateCorrelationRule(config, auth.tenant, ruleId, {
          name: payload.name,
          description: payload.description,
          ruleType: payload.ruleType,
          conditions: payload.conditions,
          isActive: payload.isActive,
        });

        if (!updated) {
          sendError(response, context, config, 404, 'not_found', 'Correlation rule not found', null, baseExtraHeaders);
          return true;
        }

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.correlation_rule.updated',
          targetType: 'correlation_rule',
          targetId: String(ruleId),
          payload: { fields: Object.keys(payload) },
        });

        sendJson(response, context, config, 200, updated, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ============================
    // Connector Sync Route
    // ============================

    if (context.path === '/v1/threat-intel/siem/sync-connectors') {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'Connector sync requires authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) {
        return true;
      }

      try {
        const limit = toSafeInteger(context.url.searchParams.get('limit'), 50, 1, 200);
        const connectorAlerts = await fetchConnectorIncidents(config, auth.tenant, limit, log);

        let ingested = 0;
        const errors = [];
        for (const alert of connectorAlerts) {
          try {
            const siemAlert = await ingestSiemAlert(config, {
              tenant: auth.tenant,
              source: alert.source || 'connector',
              alertId: alert.id,
              ruleName: alert.title,
              severity: alert.severity,
              category: 'connector_sync',
              rawPayload: alert,
              eventTime: alert.detectedAt,
            });
            notifyAlertIngested(auth.tenant, siemAlert);
            ingested += 1;
          } catch (ingestErr) {
            errors.push({ alertId: alert.id, source: alert.source, error: ingestErr.message || 'ingestion failed' });
          }
        }

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.siem.connector_sync',
          targetType: 'siem_alerts',
          targetId: null,
          payload: { fetched: connectorAlerts.length, ingested, errorCount: errors.length },
        });

        sendJson(response, context, config, 200, {
          fetched: connectorAlerts.length,
          ingested,
          errors: errors.slice(0, 10),
        }, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ============================
    // Correlation Engine Route
    // ============================

    if (context.path === '/v1/threat-intel/siem/correlate-all') {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'Correlation engine requires authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) {
        return true;
      }

      try {
        const result = await runCorrelationEngine(config, auth.tenant, log, { notifyIncidentCreated, executePlaybook });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.siem.correlation_run',
          targetType: 'correlation_engine',
          targetId: null,
          payload: { rulesEvaluated: result.evaluated, correlationsCreated: result.correlations.length },
        });

        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ============================
    // SIEM Alert Export Route
    // ============================

    if (context.path === '/v1/threat-intel/siem/export') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'SIEM export requires authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'executive_viewer');
      if (!auth) {
        return true;
      }

      try {
        const format = context.url.searchParams.get('format') || 'json';
        const severity = context.url.searchParams.get('severity');
        const source = context.url.searchParams.get('source');
        const correlated = context.url.searchParams.get('correlated');
        const startTime = context.url.searchParams.get('startTime');
        const endTime = context.url.searchParams.get('endTime');
        const limit = toSafeInteger(context.url.searchParams.get('limit'), 1000, 1, 10000);

        const result = await listSiemAlerts(config, auth.tenant, {
          limit,
          offset: 0,
          severity,
          source,
          correlated: correlated === 'true' ? true : correlated === 'false' ? false : undefined,
          startTime,
          endTime,
        });

        const alerts = result.data || [];

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.siem.exported',
          targetType: 'siem_alerts',
          targetId: null,
          payload: { format, alertCount: alerts.length, filters: { severity, source, correlated, startTime, endTime } },
        });

        if (format === 'csv') {
          const csvHeader = 'id,alert_id,source,rule_name,severity,category,source_ip,dest_ip,hostname,correlated,incident_id,event_time,ingested_at';
          const csvRows = alerts.map(a =>
            [a.id, a.alert_id || '', a.source, a.rule_name || '', a.severity, a.category || '', a.source_ip || '', a.dest_ip || '', a.hostname || '', a.correlated, a.incident_id || '', a.event_time || '', a.ingested_at || '']
              .map(v => `"${String(v).replace(/"/g, '""')}"`)
              .join(',')
          );
          const csvContent = [csvHeader, ...csvRows].join('\n');

          const headers = {
            ...baseExtraHeaders,
            'Content-Type': 'text/csv; charset=utf-8',
            'Content-Disposition': `attachment; filename="siem-alerts-${auth.tenant}-${new Date().toISOString().slice(0, 10)}.csv"`,
          };
          response.writeHead(200, headers);
          response.end(csvContent);
        } else {
          // JSON export (default)
          const exportPayload = {
            exportedAt: new Date().toISOString(),
            tenant: auth.tenant,
            totalExported: alerts.length,
            filters: { severity, source, correlated, startTime, endTime },
            alerts,
          };

          const headers = {
            ...baseExtraHeaders,
            'Content-Type': 'application/json; charset=utf-8',
            'Content-Disposition': `attachment; filename="siem-alerts-${auth.tenant}-${new Date().toISOString().slice(0, 10)}.json"`,
          };
          response.writeHead(200, headers);
          response.end(JSON.stringify(exportPayload, null, 2));
        }
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ============================
    // SOC Operations Routes
    // ============================

    // Bulk status update
    if (context.path === '/v1/threat-intel/siem/alerts/bulk-status') {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Bulk alert operations require authenticated session');
      if (!session) return true;
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) return true;

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) return true;
      if (!validateBodyShape(context, response, baseExtraHeaders, payload, {
        required: ['alertIds', 'status'],
        optional: ['notes'],
      })) return true;

      try {
        const result = await bulkUpdateAlertStatus(config, auth.tenant, {
          alertIds: payload.alertIds,
          status: payload.status,
          userId: session.user.id,
          notes: payload.notes,
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'siem_alert.bulk_status_changed',
          targetType: 'siem_alerts',
          targetId: null,
          payload: { status: payload.status, count: payload.alertIds?.length, updated: result.updated },
        });

        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // SLA metrics
    if (context.path === '/v1/threat-intel/siem/alerts/sla-metrics') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'SLA metrics require authenticated session');
      if (!session) return true;
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'executive_viewer');
      if (!auth) return true;

      try {
        const metrics = await getAlertSlaMetrics(config, auth.tenant);
        sendJson(response, context, config, 200, { metrics }, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // Attack map data
    if (context.path === '/v1/threat-intel/siem/attack-map') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Attack map requires authenticated session');
      if (!session) return true;
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'executive_viewer');
      if (!auth) return true;

      try {
        const mapData = await getAttackMapData(config, auth.tenant);
        sendJson(response, context, config, 200, mapData, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // Tenant analysts list
    if (context.path === '/v1/threat-intel/analysts') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Analyst list requires authenticated session');
      if (!session) return true;
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) return true;

      try {
        const analysts = await listTenantAnalysts(config, auth.tenant);
        sendJson(response, context, config, 200, analysts, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // Triage suggestion for specific alert
    if (/^\/v1\/threat-intel\/siem\/alerts\/[0-9]+\/triage-suggestion$/.test(context.path)) {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Triage suggestion requires authenticated session');
      if (!session) return true;
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) return true;

      try {
        const alertId = context.path.split('/')[5];
        const suggestion = await getAlertTriageSuggestion(config, auth.tenant, alertId, {
          requestId: context.requestId,
          tenantSlug: auth.tenant,
          actorId: session.user.id,
          actorEmail: session.user.email,
          ipAddress: context.clientIp || null,
          userAgent: context.userAgent || null,
        });
        if (!suggestion) {
          sendError(response, context, config, 404, 'not_found', 'Alert not found', null, baseExtraHeaders);
          return true;
        }
        sendJson(response, context, config, 200, suggestion, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // Alert notes update
    if (/^\/v1\/threat-intel\/siem\/alerts\/[0-9]+\/notes$/.test(context.path)) {
      if (context.method !== 'PATCH') {
        sendMethodNotAllowed(response, context, config, ['PATCH'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Notes update requires authenticated session');
      if (!session) return true;
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) return true;

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) return true;

      try {
        const alertId = context.path.split('/')[5];
        const result = await updateAlertNotes(config, auth.tenant, alertId, {
          notes: payload.notes,
          userId: session.user.id,
        });

        if (!result) {
          sendError(response, context, config, 404, 'not_found', 'Alert not found', null, baseExtraHeaders);
          return true;
        }

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'siem_alert.notes_updated',
          targetType: 'siem_alert',
          targetId: String(alertId),
          payload: {},
        });

        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ============================
    // Threat Hunting Routes
    // ============================

    if (context.path === '/v1/threat-intel/hunts') {
      if (context.method === 'GET') {
        if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
          return true;
        }
        const session = await requireSession(context, response, baseExtraHeaders, 'Threat hunts require authenticated session');
        if (!session) {
          return true;
        }
        const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
        if (!auth) {
          return true;
        }

        try {
          const limit = toSafeInteger(context.url.searchParams.get('limit'), 50, 1, 200);
          const offset = toSafeInteger(context.url.searchParams.get('offset'), 0, 0, 50_000);
          const queryType = context.url.searchParams.get('queryType') || undefined;

          const result = await listThreatHuntQueries(config, auth.tenant, { limit, offset, queryType });

          await meterUsage(context, session, auth.tenant, auth.product.productKey, 'threat_hunts_view', 1, {});

          sendJson(response, context, config, 200, result, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      if (context.method === 'POST') {
        if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
          return true;
        }
        const session = await requireSession(context, response, baseExtraHeaders, 'Threat hunt creation requires authenticated session');
        if (!session) {
          return true;
        }
        const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
        if (!auth) {
          return true;
        }

        const payload = await parseJsonBody(context, response, baseExtraHeaders);
        if (!payload) {
          return true;
        }
        if (!validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['name', 'queryText'],
          optional: ['description', 'queryType', 'dataSource'],
        })) {
          return true;
        }

        try {
          const hunt = await createThreatHuntQuery(config, {
            tenant: auth.tenant,
            name: payload.name,
            description: payload.description,
            queryType: payload.queryType,
            queryText: payload.queryText,
            dataSource: payload.dataSource,
            createdBy: session.user.id,
          });

          await appendAuditLog(config, {
            ...actorMetaFromContext(context, session),
            tenantSlug: auth.tenant,
            action: 'threat_intel.threat_hunt.created',
            targetType: 'threat_hunt_query',
            targetId: String(hunt?.id),
            payload: { name: payload.name, queryType: payload.queryType },
          });

          await meterUsage(context, session, auth.tenant, auth.product.productKey, 'threat_hunt_create', 1, {});

          sendJson(response, context, config, 201, hunt, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      sendMethodNotAllowed(response, context, config, ['GET', 'POST'], baseExtraHeaders);
      return true;
    }

    if (/^\/v1\/threat-intel\/hunts\/[0-9]+\/execute$/.test(context.path)) {
      if (context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['POST'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }
      const session = await requireSession(context, response, baseExtraHeaders, 'Threat hunt execution requires authenticated session');
      if (!session) {
        return true;
      }
      const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
      if (!auth) {
        return true;
      }

      try {
        const queryId = context.path.split('/')[4];
        const result = await executeThreatHuntQuery(config, auth.tenant, queryId);

        if (!result) {
          sendError(response, context, config, 404, 'not_found', 'Threat hunt query not found', null, baseExtraHeaders);
          return true;
        }

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: auth.tenant,
          action: 'threat_intel.threat_hunt.executed',
          targetType: 'threat_hunt_query',
          targetId: String(queryId),
          payload: { resultCount: result.resultCount },
        });

        await meterUsage(context, session, auth.tenant, auth.product.productKey, 'threat_hunt_execute', 1, {
          resultCount: result.resultCount,
        });

        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (/^\/v1\/threat-intel\/hunts\/[0-9]+$/.test(context.path)) {
      const huntId = context.path.split('/')[4];

      if (context.method === 'PUT') {
        if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
          return true;
        }
        const session = await requireSession(context, response, baseExtraHeaders, 'Threat hunt update requires authenticated session');
        if (!session) {
          return true;
        }
        const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
        if (!auth) {
          return true;
        }

        const payload = await parseJsonBody(context, response, baseExtraHeaders);
        if (!payload) {
          return true;
        }

        try {
          const updated = await updateThreatHuntQuery(config, auth.tenant, huntId, {
            name: payload.name,
            description: payload.description,
            queryType: payload.queryType,
            queryText: payload.queryText,
            dataSource: payload.dataSource,
          });

          if (!updated) {
            sendError(response, context, config, 404, 'not_found', 'Threat hunt query not found', null, baseExtraHeaders);
            return true;
          }

          await appendAuditLog(config, {
            ...actorMetaFromContext(context, session),
            tenantSlug: auth.tenant,
            action: 'threat_intel.threat_hunt.updated',
            targetType: 'threat_hunt_query',
            targetId: String(huntId),
            payload: { fields: Object.keys(payload) },
          });

          sendJson(response, context, config, 200, updated, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      if (context.method === 'DELETE') {
        if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
          return true;
        }
        const session = await requireSession(context, response, baseExtraHeaders, 'Threat hunt deletion requires authenticated session');
        if (!session) {
          return true;
        }
        const auth = await threatAuthChain(context, response, baseExtraHeaders, session, 'security_analyst');
        if (!auth) {
          return true;
        }

        try {
          const deleted = await deleteThreatHuntQuery(config, auth.tenant, huntId);

          await appendAuditLog(config, {
            ...actorMetaFromContext(context, session),
            tenantSlug: auth.tenant,
            action: 'threat_intel.threat_hunt.deleted',
            targetType: 'threat_hunt_query',
            targetId: String(huntId),
            payload: { deleted },
          });

          sendJson(response, context, config, 200, { deleted }, baseExtraHeaders);
        } catch (error) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
        }
        return true;
      }

      sendMethodNotAllowed(response, context, config, ['PUT', 'DELETE'], baseExtraHeaders);
      return true;
    }

    return false;
  });
}

module.exports = {
  routes,
  registerRoutes,
};
