const routes = [
  { method: 'GET', path: '/v1/compliance/soc2/controls' },
  { method: 'GET', path: '/v1/compliance/soc2/status' },
  { method: 'PATCH', path: '/v1/compliance/soc2/status/:controlId' },
  { method: 'POST', path: '/v1/compliance/soc2/evidence/upload' },
  { method: 'POST', path: '/v1/compliance/policy/generate' },
  { method: 'POST', path: '/v1/compliance/audit-package/generate' },
  { method: 'GET', path: '/v1/compliance/audit-package/:id/download' },
  // Multi-framework compliance
  { method: 'GET', path: '/v1/compliance/frameworks' },
  { method: 'GET', path: '/v1/compliance/frameworks/:frameworkId/controls' },
  { method: 'GET', path: '/v1/compliance/frameworks/:frameworkId/status' },
  { method: 'PATCH', path: '/v1/compliance/frameworks/:frameworkId/status/:controlId' },
  { method: 'GET', path: '/v1/compliance/summary' },
  // Policy approval workflow
  { method: 'PATCH', path: '/v1/compliance/policies/:policyId/status' },
  { method: 'GET', path: '/v1/compliance/policies' },
];

function registerRoutes(routerContext) {
  const register = routerContext?.register;
  if (typeof register !== 'function') {
    throw new Error('compliance-engine routes require routerContext.register(handler)');
  }

  const deps = routerContext.deps || {};
  const {
    config,
    pipeline,
    sendJson,
    sendError,
    sendMethodNotAllowed,
    requireDatabaseConfigured,
    requireSession,
    resolveTenantForRequest,
    requireProductAccess,
    requireFeatureFlagEnabled,
    listSoc2Controls,
    handleServiceFailure,
    listSoc2Status,
    computeComplianceGap,
    listSoc2Evidence,
    parseJsonBody,
    validateBodyShape,
    upsertSoc2Status,
    appendAuditLog,
    actorMetaFromContext,
    meterUsage,
    parseMultipartForm,
    sniffMimeType,
    enforceUploadPolicy,
    allowedComplianceEvidenceMimeTypes,
    computeSha256Hex,
    storageAdapter,
    normalizeUploadFileName,
    createSoc2EvidenceRecord,
    generatePolicyDraft,
    createPolicyRecord,
    log,
    buildAuditPackage,
    listPolicies,
    createAuditPackageRecord,
    getAuditPackageRecord,
    escapeContentDispositionFileName,
    // Multi-framework compliance
    listComplianceFrameworks,
    getComplianceFramework,
    listFrameworkControls,
    listFrameworkControlStatus,
    upsertFrameworkControlStatus,
    computeFrameworkGap,
    getComplianceSummary,
    // Real-time Notifications
    notifyComplianceStatusChanged,
    // Policy approval workflow
    getPolicyRecord,
    updatePolicyStatus,
  } = deps;

  register(async ({ context, response, baseExtraHeaders }) => {
    if (context.path === '/v1/compliance/soc2/controls') {
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
        'SOC2 controls require authenticated session'
      );
      if (!session) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant'),
        { allowCrossTenantRoles: ['super_admin'] }
      );
      if (!tenant) {
        return true;
      }

      const product = await requireProductAccess(
        context,
        response,
        baseExtraHeaders,
        session,
        tenant,
        'resilience-hq',
        'executive_viewer'
      );
      if (!product) {
        return true;
      }
      if (!(await requireFeatureFlagEnabled(
        context,
        response,
        baseExtraHeaders,
        tenant,
        'product_compliance_engine_enabled'
      ))) {
        return true;
      }

      try {
        const controls = await listSoc2Controls(config);

        await meterUsage(context, session, tenant, product.productKey, 'soc2_controls_view', 1, {
          controlsCount: Array.isArray(controls) ? controls.length : 0,
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'compliance.soc2_controls.viewed',
          targetType: 'soc2_control',
          targetId: 'catalog',
          payload: {
            controlsCount: Array.isArray(controls) ? controls.length : 0,
          },
        });

        sendJson(response, context, config, 200, controls, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/compliance/soc2/status') {
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
        'SOC2 status requires authenticated session'
      );
      if (!session) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant'),
        { allowCrossTenantRoles: ['super_admin'] }
      );
      if (!tenant) {
        return true;
      }

      const product = await requireProductAccess(
        context,
        response,
        baseExtraHeaders,
        session,
        tenant,
        'resilience-hq',
        'executive_viewer'
      );
      if (!product) {
        return true;
      }
      if (!(await requireFeatureFlagEnabled(
        context,
        response,
        baseExtraHeaders,
        tenant,
        'product_compliance_engine_enabled'
      ))) {
        return true;
      }

      try {
        const controls = await listSoc2Status(config, tenant);
        const gap = computeComplianceGap(controls);
        const evidence = await listSoc2Evidence(config, tenant, { limit: 20, offset: 0 });

        await meterUsage(context, session, tenant, product.productKey, 'soc2_status_view', 1, {
          controlsCount: Array.isArray(controls) ? controls.length : 0,
          evidencePreviewCount: Array.isArray(evidence?.data) ? evidence.data.length : 0,
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'compliance.soc2_status.viewed',
          targetType: 'soc2_status',
          targetId: 'tenant_overview',
          payload: {
            controlsCount: Array.isArray(controls) ? controls.length : 0,
          },
        });

        sendJson(
          response,
          context,
          config,
          200,
          {
            controls,
            gap,
            evidencePreview: evidence.data,
          },
          baseExtraHeaders
        );
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (/^\/v1\/compliance\/soc2\/status\/[A-Za-z0-9.-]+$/.test(context.path)) {
      if (context.method !== 'PATCH') {
        sendMethodNotAllowed(response, context, config, ['PATCH'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'SOC2 status update requires authenticated session'
      );
      if (!session) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant'),
        { allowCrossTenantRoles: ['super_admin'] }
      );
      if (!tenant) {
        return true;
      }

      const product = await requireProductAccess(
        context,
        response,
        baseExtraHeaders,
        session,
        tenant,
        'resilience-hq',
        'compliance_officer'
      );
      if (!product) {
        return true;
      }
      if (!(await requireFeatureFlagEnabled(
        context,
        response,
        baseExtraHeaders,
        tenant,
        'product_compliance_engine_enabled'
      ))) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }
      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['status'],
          optional: ['ownerUserId', 'notes'],
        })
      ) {
        return true;
      }

      try {
        const controlId = context.path.split('/')[5];
        const statusRecord = await upsertSoc2Status(config, {
          tenant,
          controlId,
          status: payload.status,
          ownerUserId: payload.ownerUserId,
          notes: payload.notes,
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'compliance.soc2_status.updated',
          targetType: 'soc2_control',
          targetId: statusRecord.controlId,
          payload: {
            status: statusRecord.status,
            previousStatus: statusRecord.previousStatus,
          },
        });

        await meterUsage(context, session, tenant, product.productKey, 'soc2_status_update', 1, {
          controlId: statusRecord.controlId,
        });

        sendJson(response, context, config, 200, statusRecord, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/compliance/soc2/evidence/upload') {
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
        'SOC2 evidence upload requires authenticated session'
      );
      if (!session) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant'),
        { allowCrossTenantRoles: ['super_admin'] }
      );
      if (!tenant) {
        return true;
      }

      const product = await requireProductAccess(
        context,
        response,
        baseExtraHeaders,
        session,
        tenant,
        'resilience-hq',
        'compliance_officer'
      );
      if (!product) {
        return true;
      }
      if (!(await requireFeatureFlagEnabled(
        context,
        response,
        baseExtraHeaders,
        tenant,
        'product_compliance_engine_enabled'
      ))) {
        return true;
      }

      try {
        const parsed = await parseMultipartForm(context.request, {
          maxFileSize: config.aiUploadMaxBytes,
        });
        const controlId = String(parsed.fields.controlId || '').trim();
        if (!controlId) {
          sendError(
            response,
            context,
            config,
            400,
            'missing_control_id',
            'controlId is required for SOC2 evidence uploads.',
            null,
            baseExtraHeaders
          );
          return true;
        }

        const detectedMime = sniffMimeType(parsed.file.buffer);
        const policy = enforceUploadPolicy({
          fileName: parsed.file.fileName,
          clientMimeType: parsed.file.mimeType,
          sniffedMimeType: detectedMime,
          allowedMimeTypes: allowedComplianceEvidenceMimeTypes,
          maxBytes: config.aiUploadMaxBytes,
          sizeBytes: parsed.file.sizeBytes,
        });
        const checksumSha256 = computeSha256Hex(parsed.file.buffer);
        const stored = await storageAdapter.saveFile({
          tenant,
          fileName: normalizeUploadFileName(policy.safeFileName, 'soc2-evidence'),
          buffer: parsed.file.buffer,
          mimeType: policy.mimeType,
        });

        const evidence = await createSoc2EvidenceRecord(config, {
          tenant,
          controlId,
          fileName: policy.safeFileName,
          mimeType: policy.mimeType,
          sizeBytes: parsed.file.sizeBytes,
          storageKey: stored.storagePath,
          checksumSha256,
          uploadedBy: session.user.id,
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'compliance.soc2_evidence.uploaded',
          targetType: 'soc2_evidence',
          targetId: evidence.id,
          payload: {
            controlId,
            storageKey: stored.storagePath,
          },
        });
        await meterUsage(context, session, tenant, product.productKey, 'soc2_evidence_upload', 1, {
          controlId,
        });

        sendJson(response, context, config, 201, evidence, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/compliance/policy/generate') {
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
        'Policy generation requires authenticated session'
      );
      if (!session) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant'),
        { allowCrossTenantRoles: ['super_admin'] }
      );
      if (!tenant) {
        return true;
      }

      const product = await requireProductAccess(
        context,
        response,
        baseExtraHeaders,
        session,
        tenant,
        'resilience-hq',
        'compliance_officer'
      );
      if (!product) {
        return true;
      }
      if (!(await requireFeatureFlagEnabled(
        context,
        response,
        baseExtraHeaders,
        tenant,
        'product_compliance_engine_enabled'
      ))) {
        return true;
      }
      if (!(await requireFeatureFlagEnabled(
        context,
        response,
        baseExtraHeaders,
        tenant,
        'llm_features_enabled',
        {
          message:
            'LLM features are disabled for this tenant. Enable llm_features_enabled before generating policies.',
        }
      ))) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }
      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['policyKey'],
          optional: ['organization'],
        })
      ) {
        return true;
      }

      try {
        const controls = await listSoc2Status(config, tenant);
        const generated = await generatePolicyDraft(
          config,
          log,
          {
            tenant,
            policyKey: payload.policyKey,
            organization: payload.organization || tenant,
            controls,
          },
          {
            requestId: context.requestId,
            tenantSlug: tenant,
            actorId: session.user.id,
            actorEmail: session.user.email,
            ipAddress: context.clientIp || null,
            userAgent: context.userAgent || null,
          }
        );

        const policy = await createPolicyRecord(config, {
          tenant,
          policyKey: generated.policyKey,
          content: generated.content,
          createdBy: session.user.id,
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'compliance.policy.generated',
          targetType: 'policy',
          targetId: policy.id,
          payload: {
            policyKey: policy.policyKey,
            model: generated.model,
            provider: generated.provider,
          },
        });

        await meterUsage(context, session, tenant, product.productKey, 'policy_generate', 1, {
          policyKey: policy.policyKey,
        });

        sendJson(
          response,
          context,
          config,
          201,
          {
            policy,
            llm: {
              provider: generated.provider,
              model: generated.model,
              aiGenerated: generated.aiGenerated,
              groundingScore: generated.groundingScore,
              qualityGate: generated.qualityGate,
            },
          },
          baseExtraHeaders
        );
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/compliance/audit-package/generate') {
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
        'Audit package generation requires authenticated session'
      );
      if (!session) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant'),
        { allowCrossTenantRoles: ['super_admin'] }
      );
      if (!tenant) {
        return true;
      }

      const product = await requireProductAccess(
        context,
        response,
        baseExtraHeaders,
        session,
        tenant,
        'resilience-hq',
        'compliance_officer'
      );
      if (!product) {
        return true;
      }
      if (!(await requireFeatureFlagEnabled(
        context,
        response,
        baseExtraHeaders,
        tenant,
        'product_compliance_engine_enabled'
      ))) {
        return true;
      }

      try {
        const controls = await listSoc2Status(config, tenant);
        const evidence = (await listSoc2Evidence(config, tenant, { limit: 500, offset: 0 })).data;
        const policies = await listPolicies(config, tenant, 200);
        const generated = buildAuditPackage({
          tenant,
          controls,
          evidence,
          policies,
          generatedAt: new Date().toISOString(),
        });

        const stored = await storageAdapter.saveFile({
          tenant,
          fileName: normalizeUploadFileName(`audit-package-${Date.now()}.pdf`, 'audit-package'),
          buffer: generated.pdfBuffer,
          mimeType: 'application/pdf',
        });

        const auditPackage = await createAuditPackageRecord(config, {
          tenant,
          pdfStoragePath: stored.storagePath,
          manifestJson: generated.manifest,
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'compliance.audit_package.generated',
          targetType: 'audit_package',
          targetId: auditPackage.id,
          payload: {
            storagePath: stored.storagePath,
            controlsCount: generated.manifest.controlsCount,
            evidenceCount: generated.manifest.evidenceCount,
            policiesCount: generated.manifest.policiesCount,
          },
        });

        await meterUsage(context, session, tenant, product.productKey, 'audit_package_generate', 1, {
          packageId: auditPackage.id,
        });

        sendJson(response, context, config, 201, auditPackage, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (/^\/v1\/compliance\/audit-package\/[0-9]+\/download$/.test(context.path)) {
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
        'Audit package download requires authenticated session'
      );
      if (!session) {
        return true;
      }

      const tenant = await resolveTenantForRequest(
        context,
        response,
        baseExtraHeaders,
        session,
        context.url.searchParams.get('tenant'),
        { allowCrossTenantRoles: ['super_admin'] }
      );
      if (!tenant) {
        return true;
      }

      const product = await requireProductAccess(
        context,
        response,
        baseExtraHeaders,
        session,
        tenant,
        'resilience-hq',
        'executive_viewer'
      );
      if (!product) {
        return true;
      }
      if (!(await requireFeatureFlagEnabled(
        context,
        response,
        baseExtraHeaders,
        tenant,
        'product_compliance_engine_enabled'
      ))) {
        return true;
      }

      const packageId = context.path.split('/')[4];
      try {
        const auditPackage = await getAuditPackageRecord(config, tenant, packageId);
        const file = await storageAdapter.getFileStream({ storagePath: auditPackage.pdfStoragePath });
        const fileName = escapeContentDispositionFileName(`audit-package-${auditPackage.id}.pdf`);

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'compliance.audit_package.downloaded',
          targetType: 'audit_package',
          targetId: auditPackage.id,
          payload: {
            storagePath: auditPackage.pdfStoragePath,
          },
        });

        await meterUsage(context, session, tenant, product.productKey, 'audit_package_download', 1, {
          packageId: auditPackage.id,
        });

        response.statusCode = 200;
        const headers = {
          ...baseExtraHeaders,
          'Content-Type': 'application/pdf',
          'Content-Length': String(file.sizeBytes),
          'Content-Disposition': `attachment; filename="${fileName}"`,
        };
        Object.entries(headers).forEach(([key, value]) => {
          if (value !== undefined && value !== null) {
            response.setHeader(key, value);
          }
        });
        await pipeline(file.stream, response);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }

      return true;
    }

    // ─── Multi-Framework Compliance Routes ────────────────────────────

    // GET /v1/compliance/frameworks
    if (context.path === '/v1/compliance/frameworks') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Compliance frameworks require authenticated session');
      if (!session) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'), { allowCrossTenantRoles: ['super_admin'] });
      if (!tenant) return true;
      const product = await requireProductAccess(context, response, baseExtraHeaders, session, tenant, 'resilience-hq', 'executive_viewer');
      if (!product) return true;
      if (!(await requireFeatureFlagEnabled(context, response, baseExtraHeaders, tenant, 'product_compliance_engine_enabled'))) return true;
      try {
        const result = await listComplianceFrameworks(config);
        await meterUsage(context, session, tenant, product.productKey, 'compliance_frameworks_list', 1, {});
        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // GET /v1/compliance/summary
    if (context.path === '/v1/compliance/summary') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Compliance summary requires authenticated session');
      if (!session) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'), { allowCrossTenantRoles: ['super_admin'] });
      if (!tenant) return true;
      const product = await requireProductAccess(context, response, baseExtraHeaders, session, tenant, 'resilience-hq', 'executive_viewer');
      if (!product) return true;
      if (!(await requireFeatureFlagEnabled(context, response, baseExtraHeaders, tenant, 'product_compliance_engine_enabled'))) return true;
      try {
        const summary = await getComplianceSummary(config, tenant);
        await meterUsage(context, session, tenant, product.productKey, 'compliance_summary_view', 1, {});
        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'compliance.summary.viewed',
          targetType: 'compliance_summary',
          targetId: 'all_frameworks',
          payload: { frameworkCount: summary.frameworks.length },
        });
        sendJson(response, context, config, 200, summary, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // GET /v1/compliance/frameworks/:frameworkId/controls
    if (/^\/v1\/compliance\/frameworks\/[a-z0-9_-]+\/controls$/.test(context.path)) {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Compliance controls require authenticated session');
      if (!session) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'), { allowCrossTenantRoles: ['super_admin'] });
      if (!tenant) return true;
      const product = await requireProductAccess(context, response, baseExtraHeaders, session, tenant, 'resilience-hq', 'executive_viewer');
      if (!product) return true;
      if (!(await requireFeatureFlagEnabled(context, response, baseExtraHeaders, tenant, 'product_compliance_engine_enabled'))) return true;
      const frameworkId = context.path.split('/')[4];
      try {
        const family = context.url.searchParams.get('family') || undefined;
        const result = await listFrameworkControls(config, frameworkId, { family });
        await meterUsage(context, session, tenant, product.productKey, 'compliance_controls_list', 1, { frameworkId });
        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // GET /v1/compliance/frameworks/:frameworkId/status
    if (/^\/v1\/compliance\/frameworks\/[a-z0-9_-]+\/status$/.test(context.path)) {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Framework status requires authenticated session');
      if (!session) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'), { allowCrossTenantRoles: ['super_admin'] });
      if (!tenant) return true;
      const product = await requireProductAccess(context, response, baseExtraHeaders, session, tenant, 'resilience-hq', 'executive_viewer');
      if (!product) return true;
      if (!(await requireFeatureFlagEnabled(context, response, baseExtraHeaders, tenant, 'product_compliance_engine_enabled'))) return true;
      const frameworkId = context.path.split('/')[4];
      try {
        const controls = await listFrameworkControlStatus(config, tenant, frameworkId);
        const gap = computeFrameworkGap(controls);
        await meterUsage(context, session, tenant, product.productKey, 'compliance_framework_status_view', 1, { frameworkId });
        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'compliance.framework_status.viewed',
          targetType: 'compliance_framework',
          targetId: frameworkId,
          payload: { controlsCount: controls.length },
        });
        sendJson(response, context, config, 200, { controls, gap }, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // PATCH /v1/compliance/frameworks/:frameworkId/status/:controlId
    if (/^\/v1\/compliance\/frameworks\/[a-z0-9_-]+\/status\/[A-Za-z0-9._-]+$/.test(context.path)) {
      if (context.method !== 'PATCH') {
        sendMethodNotAllowed(response, context, config, ['PATCH'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Compliance status update requires authenticated session');
      if (!session) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'), { allowCrossTenantRoles: ['super_admin'] });
      if (!tenant) return true;
      const product = await requireProductAccess(context, response, baseExtraHeaders, session, tenant, 'resilience-hq', 'compliance_officer');
      if (!product) return true;
      if (!(await requireFeatureFlagEnabled(context, response, baseExtraHeaders, tenant, 'product_compliance_engine_enabled'))) return true;

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) return true;
      if (!validateBodyShape(context, response, baseExtraHeaders, payload, {
        required: ['status'],
        optional: ['ownerUserId', 'notes'],
      })) return true;

      const segments = context.path.split('/');
      const frameworkId = segments[4];
      const controlId = segments[6];
      try {
        const record = await upsertFrameworkControlStatus(config, {
          tenant,
          frameworkId,
          controlId,
          status: payload.status,
          ownerUserId: payload.ownerUserId,
          notes: payload.notes,
        });
        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'compliance.framework_control_status.updated',
          targetType: 'compliance_control',
          targetId: `${frameworkId}/${controlId}`,
          payload: { status: record.status, previousStatus: record.previousStatus },
        });
        await meterUsage(context, session, tenant, product.productKey, 'compliance_control_status_update', 1, { frameworkId, controlId });
        notifyComplianceStatusChanged(tenant, frameworkId, controlId, record.status);
        sendJson(response, context, config, 200, record, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // ─── Policy Approval Workflow ─────────────────────────────────────

    // GET /v1/compliance/policies — list policies with approval status
    if (context.path === '/v1/compliance/policies') {
      if (context.method !== 'GET') {
        sendMethodNotAllowed(response, context, config, ['GET'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Policies list requires authenticated session');
      if (!session) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'), { allowCrossTenantRoles: ['super_admin'] });
      if (!tenant) return true;
      const product = await requireProductAccess(context, response, baseExtraHeaders, session, tenant, 'resilience-hq', 'executive_viewer');
      if (!product) return true;
      if (!(await requireFeatureFlagEnabled(context, response, baseExtraHeaders, tenant, 'product_compliance_engine_enabled'))) return true;
      try {
        const policies = await listPolicies(config, tenant, 100);
        await meterUsage(context, session, tenant, product.productKey, 'policies_list', 1, {});
        sendJson(response, context, config, 200, { data: policies }, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    // PATCH /v1/compliance/policies/:policyId/status — approve/reject/submit policy
    if (/^\/v1\/compliance\/policies\/[0-9]+\/status$/.test(context.path)) {
      if (context.method !== 'PATCH') {
        sendMethodNotAllowed(response, context, config, ['PATCH'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Policy status update requires authenticated session');
      if (!session) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'), { allowCrossTenantRoles: ['super_admin'] });
      if (!tenant) return true;
      const product = await requireProductAccess(context, response, baseExtraHeaders, session, tenant, 'resilience-hq', 'compliance_officer');
      if (!product) return true;
      if (!(await requireFeatureFlagEnabled(context, response, baseExtraHeaders, tenant, 'product_compliance_engine_enabled'))) return true;

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) return true;
      if (!validateBodyShape(context, response, baseExtraHeaders, payload, {
        required: ['status'],
        optional: ['rejectionReason'],
      })) return true;

      const policyId = context.path.split('/')[4];
      try {
        const result = await updatePolicyStatus(config, {
          tenant,
          policyId,
          status: payload.status,
          actorId: session.user.id,
          rejectionReason: payload.rejectionReason,
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: `compliance.policy.${result.status}`,
          targetType: 'policy',
          targetId: result.id,
          payload: {
            status: result.status,
            previousStatus: result.previousStatus,
            policyKey: result.policyKey,
          },
        });
        await meterUsage(context, session, tenant, product.productKey, 'policy_status_update', 1, { policyId });
        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    return false;
  });
}

module.exports = {
  routes,
  registerRoutes,
};
