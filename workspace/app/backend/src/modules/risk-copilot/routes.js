const { SCORING_FORMULA, SCORING_WEIGHTS, SEVERITY_THRESHOLDS } = require('../../ai/risk-engine');

const routes = [
  { method: 'POST', path: '/v1/risk/ingest/aws-logs' },
  { method: 'POST', path: '/v1/risk/score/compute' },
  { method: 'GET', path: '/v1/risk/findings' },
  { method: 'PATCH', path: '/v1/risk/findings/:id/treatment' },
  { method: 'POST', path: '/v1/risk/report/generate' },
  { method: 'GET', path: '/v1/risk/report/:id/download' },
];

function registerRoutes(routerContext) {
  const register = routerContext?.register;
  if (typeof register !== 'function') {
    throw new Error('risk-copilot routes require routerContext.register(handler)');
  }

  const deps = routerContext.deps || {};
  const {
    config,
    log,
    pipeline,
    sendJson,
    sendError,
    sendMethodNotAllowed,
    requireDatabaseConfigured,
    requireSession,
    resolveTenantForRequest,
    requireProductAccess,
    requireFeatureFlagEnabled,
    parseMultipartForm,
    sniffMimeType,
    enforceUploadPolicy,
    allowedAwsLogMimeTypes,
    parseAwsLogJsonBuffer,
    ingestAwsLogRecords,
    actorMetaFromContext,
    meterUsage,
    appendAuditLog,
    handleServiceFailure,
    parseJsonBody,
    validateBodyShape,
    toSafeInteger,
    listRiskFindings,
    getRiskPortfolioSummary,
    generateRiskExplanation,
    buildLocalMitigationSuggestions,
    generateRiskReportPdf,
    storageAdapter,
    normalizeUploadFileName,
    createRiskReportRecord,
    getRiskReportRecord,
    escapeContentDispositionFileName,
    updateRiskFindingTreatment,
  } = deps;

  register(async ({ context, response, baseExtraHeaders }) => {
    if (context.path === '/v1/risk/ingest/aws-logs') {
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
        'Risk ingestion requires authenticated session'
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
        'risk-copilot',
        'security_analyst'
      );
      if (!product) {
        return true;
      }

      if (!(await requireFeatureFlagEnabled(
        context,
        response,
        baseExtraHeaders,
        tenant,
        'product_risk_copilot_enabled'
      ))) {
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
          allowedMimeTypes: allowedAwsLogMimeTypes,
          maxBytes: config.aiUploadMaxBytes,
          sizeBytes: parsed.file.sizeBytes,
        });

        if (policy.mimeType !== 'application/json') {
          sendError(
            response,
            context,
            config,
            415,
            'invalid_aws_log_mime',
            'AWS ingestion accepts JSON uploads only.',
            null,
            baseExtraHeaders
          );
          return true;
        }

        const normalized = parseAwsLogJsonBuffer(parsed.file.buffer);
        const ingestResult = await ingestAwsLogRecords(
          config,
          tenant,
          session.user.id,
          normalized.records,
          actorMetaFromContext(context, session)
        );

        await meterUsage(
          context,
          session,
          tenant,
          product.productKey,
          'risk_ingest_upload',
          Math.max(1, normalized.count),
          {
            uploadedRecords: normalized.count,
          }
        );

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'risk.aws_ingest.uploaded',
          targetType: 'aws_ingest_job',
          targetId: ingestResult.jobId,
          payload: {
            uploadedRecords: normalized.count,
          },
        });

        sendJson(
          response,
          context,
          config,
          201,
          {
            ...ingestResult,
            message: `Ingested ${normalized.count} AWS log records.`,
          },
          baseExtraHeaders
        );
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }

      return true;
    }

    if (context.path === '/v1/risk/score/compute') {
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
        'Risk scoring requires authenticated session'
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
        'risk-copilot',
        'security_analyst'
      );
      if (!product) {
        return true;
      }

      if (!(await requireFeatureFlagEnabled(
        context,
        response,
        baseExtraHeaders,
        tenant,
        'product_risk_copilot_enabled'
      ))) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders, { allowEmpty: true });
      if (!payload) {
        return true;
      }
      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: [],
          optional: ['limit', 'includeAi'],
        })
      ) {
        return true;
      }

      const limit = toSafeInteger(payload.limit, 100, 1, 500);
      const includeAi = payload.includeAi !== false;

      try {
        const findingResponse = await listRiskFindings(config, tenant, { limit, offset: 0 });
        const portfolio = await getRiskPortfolioSummary(config, tenant);
        let ai = null;

        if (includeAi) {
          if (!(await requireFeatureFlagEnabled(
            context,
            response,
            baseExtraHeaders,
            tenant,
            'llm_features_enabled',
            {
              message:
                'LLM features are disabled for this tenant. Enable llm_features_enabled to generate AI explanations.',
            }
          ))) {
            return true;
          }

          ai = await generateRiskExplanation(
            config,
            log,
            {
              tenant,
              findings: findingResponse.data,
              portfolio,
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
        }

        await meterUsage(context, session, tenant, product.productKey, 'risk_score_compute', 1, {
          findingCount: findingResponse.data.length,
          includeAi,
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'risk.score.computed',
          targetType: 'risk_portfolio',
          targetId: 'current',
          payload: {
            findingCount: findingResponse.data.length,
            includeAi,
          },
        });

        sendJson(
          response,
          context,
          config,
          200,
          {
            tenant,
            portfolio,
            findings: findingResponse.data,
            aiExplanation: ai,
            scoringModel: {
              formula: SCORING_FORMULA,
              weights: SCORING_WEIGHTS,
              severityThresholds: SEVERITY_THRESHOLDS,
            },
            message: findingResponse.message,
          },
          baseExtraHeaders
        );
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }

      return true;
    }

    if (context.path === '/v1/risk/findings') {
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
        'Risk findings require authenticated session'
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
        'risk-copilot',
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
        'product_risk_copilot_enabled'
      ))) {
        return true;
      }

      try {
        const limit = toSafeInteger(context.url.searchParams.get('limit'), 50, 1, 500);
        const offset = toSafeInteger(context.url.searchParams.get('offset'), 0, 0, 50_000);
        const severity = context.url.searchParams.get('severity') || '';
        const category = context.url.searchParams.get('category') || '';
        const result = await listRiskFindings(config, tenant, { limit, offset, severity, category });

        await meterUsage(context, session, tenant, product.productKey, 'risk_findings_view', 1, {
          limit,
          offset,
          severity,
          category,
          returnedCount: Array.isArray(result?.data) ? result.data.length : 0,
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'risk.findings.viewed',
          targetType: 'risk_finding',
          targetId: 'query',
          payload: {
            limit,
            offset,
            severity,
            category,
          },
        });

        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }

      return true;
    }

    // PATCH /v1/risk/findings/:id/treatment — update treatment status, ownership, residual score
    if (/^\/v1\/risk\/findings\/[0-9]+\/treatment$/.test(context.path)) {
      if (context.method !== 'PATCH') {
        sendMethodNotAllowed(response, context, config, ['PATCH'], baseExtraHeaders);
        return true;
      }
      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) return true;
      const session = await requireSession(context, response, baseExtraHeaders, 'Risk treatment update requires authenticated session');
      if (!session) return true;
      const tenant = await resolveTenantForRequest(context, response, baseExtraHeaders, session, context.url.searchParams.get('tenant'), { allowCrossTenantRoles: ['super_admin'] });
      if (!tenant) return true;
      const product = await requireProductAccess(context, response, baseExtraHeaders, session, tenant, 'risk-copilot', 'security_analyst');
      if (!product) return true;
      if (!(await requireFeatureFlagEnabled(context, response, baseExtraHeaders, tenant, 'product_risk_copilot_enabled'))) return true;

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) return true;
      if (!validateBodyShape(context, response, baseExtraHeaders, payload, {
        required: ['treatmentStatus'],
        optional: ['ownerUserId', 'residualScore', 'reviewNotes'],
      })) return true;

      const findingId = context.path.split('/')[4];
      try {
        const result = await updateRiskFindingTreatment(config, tenant, findingId, payload);

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'risk.finding.treatment_updated',
          targetType: 'risk_finding',
          targetId: result.id,
          payload: {
            treatmentStatus: result.treatmentStatus,
            previousTreatmentStatus: result.previousTreatmentStatus,
            residualScore: result.residualScore,
          },
        });
        await meterUsage(context, session, tenant, product.productKey, 'risk_finding_treatment_update', 1, { findingId: result.id });
        sendJson(response, context, config, 200, result, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/risk/report/generate') {
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
        'Risk report generation requires authenticated session'
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
        'risk-copilot',
        'security_analyst'
      );
      if (!product) {
        return true;
      }

      if (!(await requireFeatureFlagEnabled(
        context,
        response,
        baseExtraHeaders,
        tenant,
        'product_risk_copilot_enabled'
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
            'LLM features are disabled for this tenant. Enable llm_features_enabled before generating AI risk reports.',
        }
      ))) {
        return true;
      }

      try {
        const findingResponse = await listRiskFindings(config, tenant, { limit: 200, offset: 0 });
        const portfolio = await getRiskPortfolioSummary(config, tenant);
        const aiExplanation = await generateRiskExplanation(
          config,
          log,
          {
            tenant,
            findings: findingResponse.data,
            portfolio,
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

        const mitigations =
          aiExplanation?.mitigationSuggestions || buildLocalMitigationSuggestions(findingResponse.data);
        const pdfBuffer = generateRiskReportPdf({
          tenant,
          generatedAt: new Date().toISOString(),
          portfolio,
          findings: findingResponse.data,
          mitigations,
          aiExplanation,
        });

        const stored = await storageAdapter.saveFile({
          tenant,
          fileName: normalizeUploadFileName(`risk-report-${Date.now()}.pdf`, 'risk-report'),
          buffer: pdfBuffer,
          mimeType: 'application/pdf',
        });

        const report = await createRiskReportRecord(config, {
          tenant,
          createdBy: session.user.id,
          pdfStoragePath: stored.storagePath,
          summaryJson: {
            portfolio,
            aiExplanation: {
              aiGenerated: aiExplanation.aiGenerated,
              model: aiExplanation.model,
              provider: aiExplanation.provider,
              groundingScore: aiExplanation.groundingScore,
              qualityGate: aiExplanation.qualityGate,
              disclaimer: aiExplanation.disclaimer,
            },
            findingCount: findingResponse.data.length,
          },
        });

        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'risk.report.generated',
          targetType: 'risk_report',
          targetId: report.id,
          payload: {
            findingCount: findingResponse.data.length,
            storagePath: stored.storagePath,
          },
        });

        await meterUsage(context, session, tenant, product.productKey, 'risk_report_generate_pdf', 1, {
          reportId: report.id,
          findingCount: findingResponse.data.length,
        });

        sendJson(
          response,
          context,
          config,
          201,
          {
            report,
            aiExplanation: {
              explanation: aiExplanation.explanation,
              model: aiExplanation.model,
              provider: aiExplanation.provider,
              aiGenerated: aiExplanation.aiGenerated,
              mitigationSuggestions: aiExplanation.mitigationSuggestions || [],
              groundingScore: aiExplanation.groundingScore,
              disclaimer: aiExplanation.disclaimer,
            },
          },
          baseExtraHeaders
        );
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }

      return true;
    }

    if (/^\/v1\/risk\/report\/[0-9]+\/download$/.test(context.path)) {
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
        'Risk report download requires authenticated session'
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
        'risk-copilot',
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
        'product_risk_copilot_enabled'
      ))) {
        return true;
      }

      const reportId = context.path.split('/')[4];
      try {
        const report = await getRiskReportRecord(config, tenant, reportId);
        const file = await storageAdapter.getFileStream({ storagePath: report.pdfStoragePath });
        const fileName = escapeContentDispositionFileName(`risk-report-${report.id}.pdf`);
        await appendAuditLog(config, {
          ...actorMetaFromContext(context, session),
          tenantSlug: tenant,
          action: 'risk.report.downloaded',
          targetType: 'risk_report',
          targetId: report.id,
          payload: {
            storagePath: report.pdfStoragePath,
          },
        });
        await meterUsage(context, session, tenant, product.productKey, 'risk_report_download', 1, {
          reportId: report.id,
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

    return false;
  });
}

module.exports = {
  routes,
  registerRoutes,
};
