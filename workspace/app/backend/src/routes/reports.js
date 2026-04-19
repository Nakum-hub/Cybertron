function registerRoutes(routerContext) {
  const register = routerContext?.register;
  if (typeof register !== 'function') {
    throw new Error('report routes require routerContext.register(handler)');
  }

  const deps = routerContext.deps || {};
  const {
    config,
    log,
    pipeline,
    sendJson,
    sendError,
    sendMethodNotAllowed,
    baseHeaders,
    requireDatabaseConfigured,
    requireSession,
    resolveTenantForRequest,
    parseJsonBody,
    validateBodyShape,
    handleServiceFailure,
    actorMetaFromContext,
    toSafeInteger,
    requireRole,
    requireProductAccess,
    parseMultipartForm,
    sniffMimeType,
    enforceUploadPolicy,
    computeSha256Hex,
    normalizeIdempotencyKey,
    findReportByIdempotencyKey,
    findReportByChecksum,
    createReport,
    getReportById,
    logReportDownload,
    listReports,
    listAuditLogs,
    allowedReportMimeTypes,
    parseMetadataField,
    storageAdapter,
    meterUsage,
    escapeContentDispositionFileName,
    ServiceError,
    getTenantPlan,
    assertFeatureAllowed,
  } = deps;

  register(async ({ context, response, baseExtraHeaders }) => {
    async function requireCrudProductGate(session, tenant, productKey, requiredRole, options = {}) {
      return requireProductAccess(
        context,
        response,
        baseExtraHeaders,
        session,
        tenant,
        productKey,
        requiredRole,
        options
      );
    }

    async function requirePlanFeatureGate(tenant, featureKey, featureContext = {}) {
      try {
        const plan = await getTenantPlan(config, tenant);
        assertFeatureAllowed(plan, featureKey, featureContext);
        return plan;
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
        return null;
      }
    }

    if (context.path === '/v1/reports/upload') {
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
        'Report upload requires authentication'
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

      const resilienceProduct = await requireCrudProductGate(
        session,
        tenant,
        'resilience-hq',
        'security_analyst'
      );
      if (!resilienceProduct) {
        return true;
      }

      try {
        const multipart = await parseMultipartForm(context.request, {
          maxFileSize: config.reportUploadMaxBytes,
          maxFields: 20,
          maxFieldSize: 64 * 1024,
        });

        const idempotencyKey = normalizeIdempotencyKey(
          context.request.headers['idempotency-key'] || multipart.fields.idempotencyKey
        );
        if (idempotencyKey) {
          const idempotentHit = await findReportByIdempotencyKey(config, tenant, idempotencyKey);
          if (idempotentHit) {
            await meterUsage(
              context,
              session,
              tenant,
              'resilience-hq',
              'reports.upload.idempotent',
              1,
              { reportId: idempotentHit.id }
            );
            sendJson(
              response,
              context,
              config,
              200,
              {
                report: idempotentHit,
                idempotent: true,
                message: 'Reused existing report for this idempotency key.',
              },
              baseExtraHeaders
            );
            return true;
          }
        }

        const sniffedMimeType = sniffMimeType(multipart.file.buffer);
        const policy = enforceUploadPolicy({
          fileName: multipart.file.fileName,
          clientMimeType: multipart.file.mimeType,
          sniffedMimeType,
          sizeBytes: multipart.file.sizeBytes,
          maxBytes: config.reportUploadMaxBytes,
          allowedMimeTypes: allowedReportMimeTypes,
        });

        const checksumSha256 = computeSha256Hex(multipart.file.buffer);
        const reportType = String(multipart.fields.reportType || '').trim();
        const reportDate = String(multipart.fields.reportDate || '').trim();

        const duplicate = await findReportByChecksum(config, tenant, {
          checksumSha256,
          reportType,
          reportDate,
          fileName: policy.safeFileName,
          sizeBytes: multipart.file.sizeBytes,
        });
        if (duplicate) {
          await meterUsage(
            context,
            session,
            tenant,
            'resilience-hq',
            'reports.upload.duplicate',
            1,
            { reportId: duplicate.id }
          );
          sendJson(
            response,
            context,
            config,
            200,
            {
              report: duplicate,
              idempotent: true,
              message: 'Equivalent report already exists for this tenant.',
            },
            baseExtraHeaders
          );
          return true;
        }

        const stored = await storageAdapter.saveFile({
          tenant,
          fileName: policy.safeFileName,
          mimeType: policy.mimeType,
          buffer: multipart.file.buffer,
        });

        const metadata = {
          ...parseMetadataField(multipart.fields.metadata),
          uploadedVia: 'multipart',
          originalFileName: multipart.file.fileName || policy.safeFileName,
        };

        let report;
        try {
          report = await createReport(
            config,
            tenant,
            {
              reportType,
              reportDate,
              storagePath: stored.storagePath,
              storageProvider: storageAdapter.type,
              checksumSha256,
              fileName: policy.safeFileName,
              mimeType: policy.mimeType,
              sizeBytes: stored.sizeBytes,
              idempotencyKey,
              metadata,
            },
            actorMetaFromContext(context, session)
          );
        } catch (error) {
          const duplicateIdempotency = Boolean(
            idempotencyKey &&
              error &&
              typeof error === 'object' &&
              'code' in error &&
              error.code === '23505'
          );
          if (!duplicateIdempotency) {
            throw error;
          }

          const existing = await findReportByIdempotencyKey(config, tenant, idempotencyKey);
          if (!existing) {
            throw error;
          }

          await meterUsage(
            context,
            session,
            tenant,
            'resilience-hq',
            'reports.upload.idempotent',
            1,
            { reportId: existing.id }
          );
          sendJson(
            response,
            context,
            config,
            200,
            {
              report: existing,
              idempotent: true,
              message: 'Reused existing report for this idempotency key.',
            },
            baseExtraHeaders
          );
          return true;
        }

        sendJson(
          response,
          context,
          config,
          201,
          {
            report,
            idempotent: false,
          },
          baseExtraHeaders
        );
        await meterUsage(context, session, tenant, 'resilience-hq', 'reports.upload', 1, {
          reportId: report.id,
        });
      } catch (error) {
        if (error instanceof ServiceError) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
          return true;
        }

        if (error instanceof Error && /storage|s3|bucket/i.test(error.message)) {
          log('error', 'storage.unavailable', { error: error.message });
          sendError(
            response,
            context,
            config,
            503,
            'storage_unavailable',
            'Report storage is unavailable.',
            null,
            baseExtraHeaders
          );
          return true;
        }

        throw error;
      }
      return true;
    }

    if (/^\/v1\/reports\/[0-9]+\/download$/.test(context.path)) {
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
        'Report download requires authentication'
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

      const resilienceProduct = await requireCrudProductGate(
        session,
        tenant,
        'resilience-hq',
        'executive_viewer'
      );
      if (!resilienceProduct) {
        return true;
      }

      const reportId = context.path.split('/')[3];

      try {
        const report = await getReportById(config, tenant, reportId);
        if (!report.storagePath) {
          throw new ServiceError(
            404,
            'report_file_not_found',
            'Report file is not available for download.'
          );
        }

        const file = await storageAdapter.getFileStream({
          storagePath: report.storagePath,
        });

        const fileName = escapeContentDispositionFileName(
          report.fileName || `${report.reportType || 'report'}-${report.id}.bin`
        );
        const downloadHeaders = {
          ...baseHeaders(context, config, baseExtraHeaders),
          'Content-Type': report.mimeType || 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${fileName}"`,
        };

        if (Number(file.sizeBytes) > 0) {
          downloadHeaders['Content-Length'] = String(file.sizeBytes);
        }

        response.writeHead(200, downloadHeaders);
        await pipeline(file.stream, response);
        await logReportDownload(config, tenant, reportId, actorMetaFromContext(context, session));
        await meterUsage(context, session, tenant, 'resilience-hq', 'reports.download', 1, {
          reportId: String(reportId),
        });
      } catch (error) {
        if (error instanceof ServiceError) {
          handleServiceFailure(error, response, context, baseExtraHeaders);
          return true;
        }

        const knownMissing =
          error instanceof Error &&
          (error.message === 'storage_file_not_found' ||
            error.message === 'storage_path_missing' ||
            error.message === 'NoSuchKey');
        if (knownMissing) {
          sendError(
            response,
            context,
            config,
            404,
            'report_file_not_found',
            'Report file is not available for download.',
            null,
            baseExtraHeaders
          );
          return true;
        }

        if (error instanceof Error && /storage|s3|bucket/i.test(error.message)) {
          log('error', 'storage.unavailable', { error: error.message });
          sendError(
            response,
            context,
            config,
            503,
            'storage_unavailable',
            'Report storage is unavailable.',
            null,
            baseExtraHeaders
          );
          return true;
        }

        throw error;
      }
      return true;
    }

    if (/^\/v1\/reports\/[0-9]+$/.test(context.path)) {
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
        'Report access requires authentication'
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

      const resilienceProduct = await requireCrudProductGate(
        session,
        tenant,
        'resilience-hq',
        'executive_viewer'
      );
      if (!resilienceProduct) {
        return true;
      }

      const reportId = context.path.split('/')[3];

      try {
        const report = await getReportById(config, tenant, reportId);
        sendJson(response, context, config, 200, report, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/reports') {
      if (context.method !== 'GET' && context.method !== 'POST') {
        sendMethodNotAllowed(response, context, config, ['GET', 'POST'], baseExtraHeaders);
        return true;
      }

      if (!requireDatabaseConfigured(context, response, baseExtraHeaders)) {
        return true;
      }

      const session = await requireSession(
        context,
        response,
        baseExtraHeaders,
        'Reports require authenticated session'
      );
      if (!session) {
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

      if (context.method === 'GET') {
        if (!requireRole(session, 'executive_viewer', response, context, baseExtraHeaders)) {
          return true;
        }

        const resilienceProduct = await requireCrudProductGate(
          session,
          tenant,
          'resilience-hq',
          'executive_viewer'
        );
        if (!resilienceProduct) {
          return true;
        }

        const limit = toSafeInteger(context.url.searchParams.get('limit'), 25, 1, 200);
        const payload = await listReports(config, tenant, limit);
        sendJson(response, context, config, 200, payload, baseExtraHeaders);
        return true;
      }

      if (!requireRole(session, 'security_analyst', response, context, baseExtraHeaders)) {
        return true;
      }

      const resilienceProduct = await requireCrudProductGate(
        session,
        tenant,
        'resilience-hq',
        'security_analyst'
      );
      if (!resilienceProduct) {
        return true;
      }

      const payload = await parseJsonBody(context, response, baseExtraHeaders);
      if (!payload) {
        return true;
      }

      if (
        !validateBodyShape(context, response, baseExtraHeaders, payload, {
          required: ['reportType', 'reportDate'],
          optional: [
            'storagePath',
            'checksumSha256',
            'fileName',
            'mimeType',
            'sizeBytes',
            'metadata',
            'idempotencyKey',
            'storageProvider',
          ],
        })
      ) {
        return true;
      }

      try {
        const report = await createReport(
          config,
          tenant,
          payload,
          actorMetaFromContext(context, session)
        );
        sendJson(response, context, config, 201, report, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    if (context.path === '/v1/audit-logs') {
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
        'Audit logs require authenticated session'
      );
      if (!session) {
        return true;
      }

      if (
        !requireRole(
          session,
          'tenant_admin',
          response,
          context,
          baseExtraHeaders,
          'Tenant admin role required for audit logs'
        )
      ) {
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

      const resilienceProduct = await requireCrudProductGate(
        session,
        tenant,
        'resilience-hq',
        'tenant_admin'
      );
      if (!resilienceProduct) {
        return true;
      }

      const limit = toSafeInteger(context.url.searchParams.get('limit'), 50, 1, 500);
      const offset = toSafeInteger(context.url.searchParams.get('offset'), 0, 0, 50_000);
      const action = context.url.searchParams.get('action') || undefined;
      const actorEmail = context.url.searchParams.get('actorEmail') || undefined;
      const startDate = context.url.searchParams.get('startDate') || undefined;
      const endDate = context.url.searchParams.get('endDate') || undefined;
      const payload = await listAuditLogs(config, tenant, {
        limit,
        offset,
        action,
        actorEmail,
        startDate,
        endDate,
      });
      sendJson(response, context, config, 200, payload, baseExtraHeaders);
      return true;
    }

    if (context.path === '/v1/audit-log') {
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
        'Audit log access requires authentication'
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

      const plan = await requirePlanFeatureGate(tenant, 'auditLogAccess');
      if (!plan) {
        return true;
      }

      try {
        const limit = toSafeInteger(context.url.searchParams.get('limit'), 50, 1, 200);
        const offset = toSafeInteger(context.url.searchParams.get('offset'), 0, 0, 50_000);
        const logs = await listAuditLogs(config, tenant, { limit, offset });
        sendJson(response, context, config, 200, logs, baseExtraHeaders);
      } catch (error) {
        handleServiceFailure(error, response, context, baseExtraHeaders);
      }
      return true;
    }

    return false;
  });
}

module.exports = { registerRoutes };
