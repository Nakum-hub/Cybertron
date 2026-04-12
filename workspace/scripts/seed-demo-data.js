/**
 * Seed Demo Data — Cybertron
 *
 * Strategy: Register admin on a fixed demo tenant (first-user → tenant_admin),
 * then use that admin to create a security_analyst in the same tenant,
 * enable products for that tenant, and seed demo data.
 *
 * Idempotent — skips if data already exists.
 */

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:8001';
let bearerToken = '';

async function api(method, path, body) {
    const headers = { 'Content-Type': 'application/json' };
    if (bearerToken) headers['Authorization'] = `Bearer ${bearerToken}`;
    const res = await fetch(`${BACKEND_URL}${path}`, {
        method, headers,
        body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
        const text = await res.text().catch(() => '');
        return { _fail: true, status: res.status, body: text.slice(0, 300) };
    }
    return res.json().catch(() => ({}));
}

async function login(email, password, tenant) {
    bearerToken = '';
    const r = await api('POST', '/v1/auth/login', { email, password, tenant });
    if (r._fail) return r;
    if (r.tokens?.accessToken) bearerToken = r.tokens.accessToken;
    return r;
}

async function waitForBackend() {
    for (let i = 0; i < 30; i++) {
        try { if ((await api('GET', '/v1/system/health')).status === 'ok') return true; } catch { }
        await new Promise(r => setTimeout(r, 1000));
    }
    return false;
}

async function main() {
    const demoTenant = process.env.SEED_DEMO_TENANT || 'cybertron-demo';
    const adminEmail = `${demoTenant}.seed-admin@cybertron.dev`;
    const analystEmail = `${demoTenant}.analyst@cybertron.dev`;
    console.log('[seed] Waiting for backend...');
    if (!(await waitForBackend())) { console.error('[seed] Backend not healthy.'); process.exit(1); }

    // Check if already seeded
    const summary = await api('GET', `/v1/threats/summary?tenant=${encodeURIComponent(demoTenant)}`);
    if (summary.activeThreats > 0) { console.log('[seed] Already seeded.'); return; }

    // ─── STEP 1: Bootstrap admin on demo tenant ───
    console.log(`[seed] Bootstrapping admin on tenant "${demoTenant}"...`);
    await api('POST', '/v1/auth/register', {
        email: adminEmail,
        password: 'SeedBootstrap2026!',
        displayName: 'Seed Admin',
        tenant: demoTenant,
    });
    const adminLogin = await login(adminEmail, 'SeedBootstrap2026!', demoTenant);
    console.log(`[seed]   Admin role: ${adminLogin?.user?.role}`);

    // ─── STEP 2: Create security_analyst on demo tenant ───
    if (adminLogin?.user?.role === 'tenant_admin') {
        console.log(`[seed] Creating security_analyst on ${demoTenant}...`);
        const regAnalyst = await api('POST', '/v1/auth/register', {
            email: analystEmail,
            password: 'CybertronAnalyst2026!',
            displayName: 'SOC Analyst',
            tenant: demoTenant,
            role: 'security_analyst',
        });
        if (regAnalyst._fail && regAnalyst.status !== 409) {
            console.log(`[seed]   Analyst reg: ${regAnalyst.status} — ${regAnalyst.body}`);
        }
    } else {
        console.log('[seed] Bootstrap failed — falling back to executive_viewer.');
        await api('POST', '/v1/auth/register', {
            email: analystEmail,
            password: 'CybertronAnalyst2026!',
            displayName: 'SOC Analyst',
            tenant: demoTenant,
        });
    }

    // ─── STEP 3: Login as analyst on demo tenant ───
    const analystLogin = await login(analystEmail, 'CybertronAnalyst2026!', demoTenant);
    console.log(`[seed]   Analyst role: ${analystLogin?.user?.role}`);

    // ─── STEP 4: Enable all products for demo tenant ───
    await login(adminEmail, 'SeedBootstrap2026!', demoTenant);
    console.log(`[seed] Enabling products for ${demoTenant}...`);
    const products = ['threat-command', 'identity-guardian', 'resilience-hq', 'risk-copilot'];
    for (const pk of products) {
        const r = await api('PATCH', `/v1/tenants/${encodeURIComponent(demoTenant)}/products/${pk}`, {
            enabled: true,
            roleMin: 'executive_viewer',
        });
        if (r._fail) {
            console.log(`[seed]   ⚠ ${pk}: ${r.status} ${r.body.substring(0, 80)}`);
        } else {
            console.log(`[seed]   ✓ ${pk} enabled`);
        }
    }

    // ─── STEP 5: Seed incidents ───
    console.log('[seed] Seeding incidents...');
    const incidents = [
        { title: 'Suspicious outbound traffic to known C2 server', severity: 'critical', status: 'investigating' },
        { title: 'Brute force login attempts on admin portal', severity: 'high', status: 'investigating' },
        { title: 'Unauthorized S3 bucket policy modification', severity: 'high', status: 'investigating' },
        { title: 'Expired TLS certificate on payment gateway', severity: 'medium', status: 'resolved' },
        { title: 'Privilege escalation via misconfigured sudo', severity: 'critical', status: 'investigating' },
        { title: 'Anomalous database query volume spike', severity: 'medium', status: 'open' },
        { title: 'Phishing campaign targeting engineering team', severity: 'high', status: 'resolved' },
        { title: 'Unpatched Log4j in staging environment', severity: 'critical', status: 'open' },
    ];
    let ic = 0;
    for (const inc of incidents) {
        const r = await api('POST', `/v1/incidents?tenant=${encodeURIComponent(demoTenant)}`, inc);
        if (r._fail) console.log(`[seed]   ⚠ inc ${r.status}: ${r.body.substring(0, 80)}`);
        else ic++;
    }
    console.log(`[seed]   ✓ ${ic} incidents`);

    // ─── STEP 6: Seed IOCs ───
    console.log('[seed] Seeding IOCs...');
    const iocs = [
        { iocType: 'ip', value: '185.220.101.34', source: 'threat-intel-feed', confidence: 95 },
        { iocType: 'domain', value: 'malware-c2.evil.com', source: 'investigation', confidence: 90 },
        { iocType: 'hash', value: 'e99a18c428cb38d5f260853678922e03', source: 'sandbox', confidence: 85 },
        { iocType: 'ip', value: '91.219.236.0', source: 'threat-intel-feed', confidence: 80 },
        { iocType: 'domain', value: 'phishing-portal.com', source: 'user-report', confidence: 92 },
        { iocType: 'url', value: 'https://cdn.badactor.net/payload.js', source: 'ids-alert', confidence: 88 },
    ];
    let iocCount = 0;
    for (const ioc of iocs) {
        const r = await api('POST', `/v1/iocs?tenant=${encodeURIComponent(demoTenant)}`, ioc);
        if (!r._fail) iocCount++;
    }
    console.log(`[seed]   ✓ ${iocCount} IOCs`);

    // ─── STEP 7: Seed service requests ───
    console.log('[seed] Seeding service requests...');
    const srs = [
        { category: 'access', subject: 'VPN access for contractor team', priority: 'medium' },
        { category: 'firewall', subject: 'Firewall rule for payment service', priority: 'high' },
        { category: 'review', subject: 'Third-party SDK security review', priority: 'low' },
    ];
    let srCount = 0;
    for (const sr of srs) {
        const r = await api('POST', `/v1/service-requests?tenant=${encodeURIComponent(demoTenant)}`, sr);
        if (!r._fail) srCount++;
    }
    console.log(`[seed]   ✓ ${srCount} service requests`);

    // Verify
    const verify = await api('GET', `/v1/threats/summary?tenant=${encodeURIComponent(demoTenant)}`);
    console.log(`[seed] Verify (${demoTenant}) → activeThreats: ${verify.activeThreats}, blocked: ${verify.blockedToday}`);
    console.log('[seed] ✅ Done.');
}

main().catch(err => { console.error('[seed] Error:', err.message); process.exit(1); });
