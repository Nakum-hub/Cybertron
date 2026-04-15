function buildOpenApiSpec(config) {
  return {
    openapi: '3.0.3',
    info: {
      title: 'Cybertron Backend API',
      version: config.appVersion,
      description: 'Core API contracts for Cybertron platform and landing integrations.',
    },
    servers: [
      {
        url: '/v1',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: config.authMode === 'jwt_hs256' ? 'JWT' : 'Opaque token',
        },
      },
      schemas: {
        ErrorResponse: {
          type: 'object',
          properties: {
            error: {
              type: 'object',
              properties: {
                code: { type: 'string' },
                message: { type: 'string' },
                details: {},
                requestId: { type: 'string' },
              },
            },
          },
        },
        ThreatSummary: {
          type: 'object',
          properties: {
            activeThreats: { type: 'integer' },
            blockedToday: { type: 'integer' },
            mttrMinutes: { type: 'integer' },
            trustScore: { type: 'integer' },
          },
          required: ['activeThreats', 'blockedToday', 'mttrMinutes', 'trustScore'],
        },
        ThreatIncident: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            title: { type: 'string' },
            severity: {
              type: 'string',
              enum: ['critical', 'high', 'medium', 'low'],
            },
            detectedAt: { type: 'string', format: 'date-time' },
            status: {
              type: 'string',
              enum: ['open', 'investigating', 'resolved'],
            },
          },
          required: ['id', 'title', 'severity', 'detectedAt', 'status'],
        },
        PublicRuntimeConfig: {
          type: 'object',
          properties: {
            apiBaseUrl: { type: 'string' },
            API_BASE_URL: { type: 'string' },
            authTransport: { type: 'string', enum: ['cookie', 'bearer'] },
            csrfEnabled: { type: 'boolean' },
            csrfHeaderName: { type: 'string' },
            csrfCookieName: { type: 'string' },
            authLoginPath: { type: 'string' },
            authTokenPath: { type: 'string' },
            authMePath: { type: 'string' },
            authLogoutPath: { type: 'string' },
            tenantsPath: { type: 'string' },
            productsPath: { type: 'string' },
            tenantProductsPathTemplate: { type: 'string' },
            tenantFeatureFlagsPathTemplate: { type: 'string' },
            modulesPath: { type: 'string' },
            billingUsagePath: { type: 'string' },
            billingCreditsPath: { type: 'string' },
            threatSummaryPath: { type: 'string' },
            threatIncidentsPath: { type: 'string' },
            systemHealthPath: { type: 'string' },
            platformAppsPath: { type: 'string' },
            reportsPath: { type: 'string' },
            reportUploadPath: { type: 'string' },
            reportDownloadPathTemplate: { type: 'string' },
            analyticsEnabled: { type: 'boolean' },
            environment: { type: 'string' },
            appVersion: { type: 'string' },
            region: { type: 'string' },
          },
        },
      },
    },
    paths: {
      '/auth/login': {
        get: {
          summary: 'Demo login redirect (disabled in production)',
          responses: {
            302: { description: 'Redirect to callback with token in demo mode' },
            404: { description: 'Not exposed in production artifact' },
            503: { description: 'External identity provider required or demo auth disabled' },
          },
        },
        post: {
          summary: 'Password login (database-backed)',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['email', 'password'],
                  properties: {
                    tenant: { type: 'string', example: 'global' },
                    email: { type: 'string', format: 'email' },
                    password: { type: 'string', format: 'password' },
                  },
                },
              },
            },
          },
          responses: {
            200: { description: 'Authenticated with access + refresh token pair' },
            401: { description: 'Invalid credentials' },
            429: { description: 'Account lockout due to failed attempts' },
          },
        },
      },
      '/auth/me': {
        get: {
          summary: 'Get authenticated profile',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Authenticated profile' },
            401: { description: 'Missing/invalid token' },
          },
        },
      },
      '/auth/logout': {
        post: {
          summary: 'Logout active session',
          security: [{ bearerAuth: [] }],
          responses: {
            204: { description: 'Logged out' },
            401: { description: 'Missing/invalid token' },
          },
        },
      },
      '/auth/register': {
        post: {
          summary: 'Create user account',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['email', 'password'],
                  properties: {
                    tenant: { type: 'string' },
                    email: { type: 'string', format: 'email' },
                    password: { type: 'string', format: 'password' },
                    displayName: { type: 'string' },
                    role: {
                      type: 'string',
                      enum: [
                        'executive_viewer',
                        'compliance_officer',
                        'security_analyst',
                        'tenant_admin',
                        'super_admin',
                      ],
                    },
                  },
                },
              },
            },
          },
          responses: {
            201: { description: 'User created' },
            403: { description: 'Registration disabled or forbidden role assignment' },
            409: { description: 'Email already exists in tenant' },
          },
        },
      },
      '/auth/token': {
        post: {
          summary: 'Rotate refresh token and return new token pair',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['grantType'],
                  properties: {
                    grantType: { type: 'string', enum: ['refresh_token'] },
                    refreshToken: {
                      type: 'string',
                      description: 'Optional when refresh token is present in HttpOnly cookie.',
                    },
                  },
                },
              },
            },
          },
          responses: {
            200: { description: 'Token pair rotated successfully' },
            401: { description: 'Invalid refresh token' },
          },
        },
      },
      '/auth/password/forgot': {
        post: {
          summary: 'Request password reset token',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['email'],
                  properties: {
                    tenant: { type: 'string' },
                    email: { type: 'string', format: 'email' },
                  },
                },
              },
            },
          },
          responses: {
            200: { description: 'Reset request accepted (always non-enumerating response)' },
          },
        },
      },
      '/auth/password/reset': {
        post: {
          summary: 'Reset password with one-time token',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['tenant', 'resetToken', 'newPassword'],
                  properties: {
                    tenant: { type: 'string' },
                    resetToken: { type: 'string' },
                    newPassword: { type: 'string', format: 'password' },
                  },
                },
              },
            },
          },
          responses: {
            200: { description: 'Password reset successful' },
            400: { description: 'Invalid or expired reset token' },
          },
        },
      },
      '/threats/summary': {
        get: {
          summary: 'Tenant threat summary sourced from database/connectors',
          responses: {
            200: {
              description: 'Threat summary payload',
              content: {
                'application/json': {
                  schema: {
                    $ref: '#/components/schemas/ThreatSummary',
                  },
                },
              },
            },
          },
        },
      },
      '/threats/incidents': {
        get: {
          summary: 'Recent tenant incidents sourced from database/connectors',
          responses: {
            200: {
              description: 'Incident list payload',
              content: {
                'application/json': {
                  schema: {
                    type: 'array',
                    items: {
                      $ref: '#/components/schemas/ThreatIncident',
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/connectors/status': {
        get: {
          summary: 'Connector health and configuration state',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Connector status payload' },
            403: { description: 'Analyst role required' },
          },
        },
      },
      '/incidents': {
        get: {
          summary: 'List incidents with filters and pagination',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Incident list' },
          },
        },
        post: {
          summary: 'Create incident record',
          security: [{ bearerAuth: [] }],
          responses: {
            201: { description: 'Incident created' },
            403: { description: 'Analyst role required' },
          },
        },
      },
      '/incidents/{incidentId}': {
        patch: {
          summary: 'Update incident fields',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'incidentId',
              required: true,
              schema: { type: 'integer' },
            },
          ],
          responses: {
            200: { description: 'Incident updated' },
            404: { description: 'Incident not found' },
          },
        },
      },
      '/incidents/{incidentId}/timeline': {
        get: {
          summary: 'List timeline events for incident',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'incidentId',
              required: true,
              schema: { type: 'integer' },
            },
          ],
          responses: {
            200: { description: 'Incident timeline' },
          },
        },
      },
      '/incidents/{incidentId}/iocs/{iocId}': {
        post: {
          summary: 'Link IOC to incident',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'incidentId',
              required: true,
              schema: { type: 'integer' },
            },
            {
              in: 'path',
              name: 'iocId',
              required: true,
              schema: { type: 'integer' },
            },
          ],
          responses: {
            204: { description: 'IOC linked to incident' },
          },
        },
      },
      '/iocs': {
        get: {
          summary: 'List IOC vault entries',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'IOC list' },
          },
        },
        post: {
          summary: 'Create or upsert IOC',
          security: [{ bearerAuth: [] }],
          responses: {
            201: { description: 'IOC stored' },
          },
        },
      },
      '/platform/apps': {
        get: {
          summary: 'List platform modules accessible by role',
          responses: {
            200: { description: 'Accessible module list' },
          },
        },
      },
      '/tenants': {
        get: {
          summary: 'List tenant records (super admin)',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Tenant list' },
            403: { description: 'Access denied' },
          },
        },
      },
      '/tenants/{tenantId}/products': {
        get: {
          summary: 'List tenant product enablement and role gates',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'tenantId',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            200: { description: 'Tenant product list' },
            403: { description: 'Access denied for tenant scope' },
          },
        },
      },
      '/tenants/{tenantId}/products/{productKey}': {
        patch: {
          summary: 'Update tenant product state (tenant admin / super admin)',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'tenantId',
              required: true,
              schema: { type: 'string' },
            },
            {
              in: 'path',
              name: 'productKey',
              required: true,
              schema: { type: 'string' },
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['enabled'],
                  properties: {
                    enabled: { type: 'boolean' },
                    roleMin: {
                      type: 'string',
                      enum: [
                        'executive_viewer',
                        'compliance_officer',
                        'security_analyst',
                        'tenant_admin',
                        'super_admin',
                      ],
                    },
                  },
                },
              },
            },
          },
          responses: {
            200: { description: 'Tenant product state updated' },
            403: { description: 'Access denied' },
            404: { description: 'Product not found' },
          },
        },
      },
      '/tenants/{tenantId}/feature-flags': {
        get: {
          summary: 'List tenant feature flags',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'tenantId',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            200: { description: 'Tenant feature flags' },
            403: { description: 'Access denied' },
          },
        },
      },
      '/tenants/{tenantId}/feature-flags/{flagKey}': {
        patch: {
          summary: 'Update tenant feature flag (tenant admin / super admin)',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'tenantId',
              required: true,
              schema: { type: 'string' },
            },
            {
              in: 'path',
              name: 'flagKey',
              required: true,
              schema: { type: 'string' },
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['enabled'],
                  properties: {
                    enabled: { type: 'boolean' },
                  },
                },
              },
            },
          },
          responses: {
            200: { description: 'Tenant feature flag updated' },
            403: { description: 'Access denied' },
            404: { description: 'Feature flag not found' },
          },
        },
      },
      '/users': {
        get: {
          summary: 'List users for tenant (tenant admin+)',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'User list' },
            403: { description: 'Access denied' },
          },
        },
      },
      '/service-requests': {
        get: {
          summary: 'List service requests (tenant-scoped)',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Service request list' },
          },
        },
        post: {
          summary: 'Create service request',
          security: [{ bearerAuth: [] }],
          responses: {
            201: { description: 'Service request created' },
          },
        },
      },
      '/service-requests/{requestId}': {
        patch: {
          summary: 'Update service request workflow fields',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'requestId',
              required: true,
              schema: { type: 'integer' },
            },
          ],
          responses: {
            200: { description: 'Service request updated' },
          },
        },
      },
      '/service-requests/{requestId}/comments': {
        get: {
          summary: 'List service request comments',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'requestId',
              required: true,
              schema: { type: 'integer' },
            },
          ],
          responses: {
            200: { description: 'Comment list' },
          },
        },
        post: {
          summary: 'Add comment to service request',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'requestId',
              required: true,
              schema: { type: 'integer' },
            },
          ],
          responses: {
            200: { description: 'Comment appended' },
          },
        },
      },
      '/reports': {
        get: {
          summary: 'List reports for tenant',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Report list' },
          },
        },
        post: {
          summary: 'Create report metadata record',
          security: [{ bearerAuth: [] }],
          responses: {
            201: { description: 'Report created' },
          },
        },
      },
      '/reports/upload': {
        post: {
          summary: 'Upload report file and create metadata record',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'multipart/form-data': {
                schema: {
                  type: 'object',
                  required: ['reportType', 'reportDate', 'file'],
                  properties: {
                    reportType: { type: 'string' },
                    reportDate: { type: 'string', format: 'date' },
                    metadata: { type: 'string', description: 'JSON string object' },
                    idempotencyKey: { type: 'string' },
                    file: { type: 'string', format: 'binary' },
                  },
                },
              },
            },
          },
          responses: {
            201: { description: 'Report file uploaded and metadata persisted' },
            200: { description: 'Idempotent replay returned existing report' },
            415: { description: 'Unsupported media type' },
            413: { description: 'Upload exceeds configured maximum size' },
          },
        },
      },
      '/reports/{reportId}': {
        get: {
          summary: 'Get report metadata',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'reportId',
              required: true,
              schema: { type: 'integer' },
            },
          ],
          responses: {
            200: { description: 'Report metadata' },
            404: { description: 'Report not found' },
          },
        },
      },
      '/reports/{reportId}/download': {
        get: {
          summary: 'Download report file binary',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'reportId',
              required: true,
              schema: { type: 'integer' },
            },
          ],
          responses: {
            200: {
              description: 'Binary file stream',
              content: {
                'application/octet-stream': {
                  schema: { type: 'string', format: 'binary' },
                },
              },
            },
            404: { description: 'Report file not found' },
          },
        },
      },
      '/products': {
        get: {
          summary: 'List product catalog and tenant-enabled states',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Product catalog payload' },
          },
        },
      },
      '/products/{productId}/tenant-state': {
        patch: {
          summary: 'Enable/disable product for tenant (tenant admin+)',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'productId',
              required: true,
              schema: { type: 'string' },
            },
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['tenant', 'enabled'],
                  properties: {
                    tenant: { type: 'string' },
                    enabled: { type: 'boolean' },
                  },
                },
              },
            },
          },
          responses: {
            200: { description: 'Tenant product state updated' },
            403: { description: 'Tenant admin role required' },
            404: { description: 'Product not found' },
          },
        },
      },
      '/modules': {
        get: {
          summary: 'List registered backend modules and accessible apps',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Module registry response' },
            401: { description: 'Authentication required' },
          },
        },
      },
      '/modules/{moduleId}/status': {
        get: {
          summary: 'Get module status for tenant scope',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'moduleId',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            200: { description: 'Module status payload' },
            403: { description: 'Module not accessible for role/tenant' },
            404: { description: 'Module not found' },
          },
        },
      },
      '/billing/usage': {
        get: {
          summary: 'List tenant usage events for billing metering',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Usage events list' },
            403: { description: 'Security Analyst role required' },
          },
        },
      },
      '/billing/credits': {
        get: {
          summary: 'Get tenant credit balance',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Credit balance payload' },
            403: { description: 'Access denied' },
          },
        },
      },
      '/risk/ingest/aws-logs': {
        post: {
          summary: 'Upload AWS logs JSON and ingest tenant risk findings',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'multipart/form-data': {
                schema: {
                  type: 'object',
                  required: ['file'],
                  properties: {
                    file: { type: 'string', format: 'binary' },
                  },
                },
              },
            },
          },
          responses: {
            201: { description: 'Ingestion completed' },
            403: { description: 'Feature or role denied' },
            415: { description: 'Invalid file type' },
          },
        },
      },
      '/risk/score/compute': {
        post: {
          summary: 'Compute risk portfolio summary and optional AI explanation',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Risk scoring result' },
            503: { description: 'LLM provider not configured when AI explanation is requested' },
          },
        },
      },
      '/risk/findings': {
        get: {
          summary: 'List tenant risk findings',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Risk findings list' },
          },
        },
      },
      '/risk/report/generate': {
        post: {
          summary: 'Generate board-ready risk PDF report',
          security: [{ bearerAuth: [] }],
          responses: {
            201: { description: 'Risk report generated' },
            503: { description: 'LLM provider not configured' },
          },
        },
      },
      '/risk/report/{reportId}/download': {
        get: {
          summary: 'Download generated risk report PDF',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'reportId',
              required: true,
              schema: { type: 'integer' },
            },
          ],
          responses: {
            200: { description: 'Risk report PDF stream' },
            404: { description: 'Risk report not found' },
          },
        },
      },
      '/compliance/soc2/controls': {
        get: {
          summary: 'List SOC2 controls catalog',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'SOC2 control list' },
          },
        },
      },
      '/compliance/soc2/status': {
        get: {
          summary: 'List tenant SOC2 control statuses and gap analysis',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'SOC2 readiness payload' },
          },
        },
      },
      '/compliance/soc2/status/{controlId}': {
        patch: {
          summary: 'Update SOC2 control status',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'controlId',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            200: { description: 'Control status updated' },
            403: { description: 'Role or feature denied' },
          },
        },
      },
      '/compliance/soc2/evidence/upload': {
        post: {
          summary: 'Upload SOC2 evidence file',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'multipart/form-data': {
                schema: {
                  type: 'object',
                  required: ['controlId', 'file'],
                  properties: {
                    controlId: { type: 'string' },
                    file: { type: 'string', format: 'binary' },
                  },
                },
              },
            },
          },
          responses: {
            201: { description: 'Evidence uploaded' },
            413: { description: 'Upload too large' },
            415: { description: 'Unsupported file type' },
          },
        },
      },
      '/compliance/policy/generate': {
        post: {
          summary: 'Generate policy content via LLM',
          security: [{ bearerAuth: [] }],
          responses: {
            201: { description: 'Policy generated and persisted' },
            503: { description: 'LLM provider not configured' },
          },
        },
      },
      '/compliance/audit-package/generate': {
        post: {
          summary: 'Generate SOC2 audit package PDF',
          security: [{ bearerAuth: [] }],
          responses: {
            201: { description: 'Audit package generated' },
          },
        },
      },
      '/compliance/audit-package/{packageId}/download': {
        get: {
          summary: 'Download generated SOC2 audit package PDF',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'packageId',
              required: true,
              schema: { type: 'integer' },
            },
          ],
          responses: {
            200: { description: 'Audit package PDF stream' },
            404: { description: 'Audit package not found' },
          },
        },
      },
      '/threat-intel/cve/sync': {
        post: {
          summary: 'Sync CVE feed from NVD',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Sync complete' },
            403: { description: 'Role or feature denied' },
          },
        },
      },
      '/threat-intel/cve/feed': {
        get: {
          summary: 'List tenant CVE feed entries',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Tenant CVE feed' },
          },
        },
      },
      '/threat-intel/cve/{cveId}/summarize': {
        post: {
          summary: 'Generate plain-English CVE summary via LLM',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'cveId',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            201: { description: 'CVE summary generated' },
            503: { description: 'LLM provider not configured' },
          },
        },
      },
      '/threat-intel/dashboard': {
        get: {
          summary: 'Threat intel executive dashboard summary',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Threat intel dashboard payload' },
          },
        },
      },
      '/threat-intel/ai/runtime': {
        get: {
          summary: 'Inspect live threat AI runtime status and provider reachability',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Threat AI runtime status' },
            403: { description: 'Role or product access denied' },
          },
        },
      },
      '/threat-intel/siem/upload': {
        post: {
          summary: 'Upload SOC log JSON or NDJSON and ingest tenant SIEM alerts',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'multipart/form-data': {
                schema: {
                  type: 'object',
                  required: ['file'],
                  properties: {
                    file: { type: 'string', format: 'binary' },
                    runCorrelation: { type: 'string', enum: ['true', 'false'] },
                    source: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            201: { description: 'SOC file ingested into SIEM alerts' },
            403: { description: 'Role or feature denied' },
            415: { description: 'Invalid file type' },
          },
        },
      },
      '/ai/modules': {
        get: {
          summary: 'List AI module scaffolding catalog',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'AI modules catalog' },
          },
        },
      },
      '/ai/modules/{moduleId}': {
        get: {
          summary: 'Read AI module runtime status and descriptor',
          security: [{ bearerAuth: [] }],
          parameters: [
            {
              in: 'path',
              name: 'moduleId',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            200: { description: 'Module status payload' },
            403: { description: 'Module not accessible for role/tenant' },
            404: { description: 'Unknown module' },
          },
        },
      },
      '/audit-logs': {
        get: {
          summary: 'List audit logs (tenant admin+)',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Audit log list' },
            403: { description: 'Access denied' },
          },
        },
      },
      '/apps/{appId}/status': {
        get: {
          summary: 'Module live status',
          parameters: [
            {
              in: 'path',
              name: 'appId',
              required: true,
              schema: { type: 'string' },
            },
          ],
          responses: {
            200: { description: 'Module status' },
            403: { description: 'Role is not allowed' },
            404: { description: 'Unknown module' },
          },
        },
      },
      '/system/health': {
        get: {
          summary: 'Runtime health status',
          responses: { 200: { description: 'Healthy response' } },
        },
      },
      '/system/liveness': {
        get: {
          summary: 'Liveness probe',
          responses: { 200: { description: 'Process alive' } },
        },
      },
      '/system/readiness': {
        get: {
          summary: 'Readiness probe',
          responses: {
            200: { description: 'Ready for traffic' },
            503: { description: 'Not ready due to invalid config/dependencies' },
          },
        },
      },
      '/system/config': {
        get: {
          summary: 'Public runtime configuration for frontend',
          responses: {
            200: {
              description: 'Public runtime config',
              content: {
                'application/json': {
                  schema: {
                    $ref: '#/components/schemas/PublicRuntimeConfig',
                  },
                },
              },
            },
          },
        },
      },
      '/system/metrics': {
        get: {
          summary: 'JSON service metrics',
          responses: { 200: { description: 'Metrics payload' } },
        },
      },
      '/system/metrics/prometheus': {
        get: {
          summary: 'Prometheus metrics',
          responses: { 200: { description: 'Prometheus text format metrics' } },
        },
      },
      '/system/openapi': {
        get: {
          summary: 'OpenAPI document',
          responses: { 200: { description: 'OpenAPI JSON' } },
        },
      },

      // ─── P1/P2: Admin, Billing & Notification Routes ──────────────
      '/admin/users': {
        get: {
          summary: 'List users for workspace (tenant admin)',
          security: [{ bearerAuth: [] }],
          parameters: [{ in: 'query', name: 'tenant', schema: { type: 'string' } }],
          responses: {
            200: { description: 'User list' },
            403: { description: 'Admin role required' },
          },
        },
      },
      '/admin/invites': {
        get: {
          summary: 'List workspace invites',
          security: [{ bearerAuth: [] }],
          parameters: [{ in: 'query', name: 'tenant', schema: { type: 'string' } }],
          responses: { 200: { description: 'Invite list' } },
        },
        post: {
          summary: 'Create workspace invite',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['email', 'role'],
                  properties: {
                    email: { type: 'string', format: 'email' },
                    role: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            201: { description: 'Invite created' },
            403: { description: 'Admin role required' },
          },
        },
      },
      '/admin/invites/{inviteId}': {
        delete: {
          summary: 'Revoke workspace invite',
          security: [{ bearerAuth: [] }],
          parameters: [{ in: 'path', name: 'inviteId', required: true, schema: { type: 'integer' } }],
          responses: {
            204: { description: 'Invite revoked' },
            404: { description: 'Invite not found' },
          },
        },
      },
      '/invites/accept': {
        post: {
          summary: 'Accept workspace invite (public endpoint)',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['token'],
                  properties: {
                    token: { type: 'string' },
                    userId: { type: 'integer' },
                  },
                },
              },
            },
          },
          responses: {
            200: { description: 'Invite accepted' },
            400: { description: 'Invalid or expired token' },
          },
        },
      },
      '/admin/connectors': {
        get: {
          summary: 'List connector configurations',
          security: [{ bearerAuth: [] }],
          parameters: [{ in: 'query', name: 'tenant', schema: { type: 'string' } }],
          responses: { 200: { description: 'Connector config list' } },
        },
      },
      '/admin/connectors/{connector}': {
        put: {
          summary: 'Upsert connector configuration',
          security: [{ bearerAuth: [] }],
          parameters: [{ in: 'path', name: 'connector', required: true, schema: { type: 'string' } }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    apiUrl: { type: 'string' },
                    apiToken: { type: 'string' },
                    enabled: { type: 'boolean' },
                  },
                },
              },
            },
          },
          responses: {
            200: { description: 'Connector config saved' },
            403: { description: 'Admin role required' },
          },
        },
        delete: {
          summary: 'Delete connector configuration',
          security: [{ bearerAuth: [] }],
          parameters: [{ in: 'path', name: 'connector', required: true, schema: { type: 'string' } }],
          responses: { 204: { description: 'Connector config deleted' } },
        },
      },
      '/admin/connectors/{connector}/test': {
        post: {
          summary: 'Test connector connectivity',
          security: [{ bearerAuth: [] }],
          parameters: [{ in: 'path', name: 'connector', required: true, schema: { type: 'string' } }],
          responses: {
            200: { description: 'Connectivity test result' },
            403: { description: 'Admin role required' },
          },
        },
      },
      '/admin/api-keys': {
        get: {
          summary: 'List API keys for user',
          security: [{ bearerAuth: [] }],
          responses: { 200: { description: 'API key list' } },
        },
        post: {
          summary: 'Create API key',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['name'],
                  properties: {
                    name: { type: 'string' },
                    scopes: { type: 'array', items: { type: 'string' } },
                    expiresIn: { type: 'string', description: 'Duration string e.g. 30d, 90d' },
                  },
                },
              },
            },
          },
          responses: {
            201: { description: 'API key created (secret shown once)' },
          },
        },
      },
      '/admin/api-keys/{keyId}': {
        delete: {
          summary: 'Revoke API key',
          security: [{ bearerAuth: [] }],
          parameters: [{ in: 'path', name: 'keyId', required: true, schema: { type: 'integer' } }],
          responses: { 204: { description: 'API key revoked' } },
        },
      },
      '/billing/checkout': {
        post: {
          summary: 'Create Stripe checkout session',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    plan: { type: 'string', enum: ['pro', 'enterprise'] },
                    billingCycle: { type: 'string', enum: ['monthly', 'annual'] },
                    priceId: { type: 'string', description: 'Direct Stripe price ID override' },
                    successUrl: { type: 'string' },
                    cancelUrl: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            200: { description: 'Stripe checkout session URL' },
            503: { description: 'Stripe not configured' },
          },
        },
      },
      '/billing/status': {
        get: {
          summary: 'Get tenant subscription status',
          security: [{ bearerAuth: [] }],
          parameters: [{ in: 'query', name: 'tenant', schema: { type: 'string' } }],
          responses: {
            200: { description: 'Subscription status payload' },
          },
        },
      },
      '/billing/webhook': {
        post: {
          summary: 'Stripe webhook handler (signature-verified, no auth)',
          responses: {
            200: { description: 'Webhook processed' },
            400: { description: 'Invalid signature' },
          },
        },
      },
      '/notifications/preferences': {
        get: {
          summary: 'Get notification preferences for authenticated user',
          security: [{ bearerAuth: [] }],
          responses: {
            200: { description: 'Notification preferences payload' },
          },
        },
        patch: {
          summary: 'Update notification preferences',
          security: [{ bearerAuth: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    emailOnCritical: { type: 'boolean' },
                    emailOnHigh: { type: 'boolean' },
                    emailOnResolved: { type: 'boolean' },
                    inAppAll: { type: 'boolean' },
                  },
                },
              },
            },
          },
          responses: {
            200: { description: 'Preferences updated' },
          },
        },
      },
    },
  };
}

module.exports = {
  buildOpenApiSpec,
};
