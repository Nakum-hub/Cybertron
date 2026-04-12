#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function ensureExists(filePath) {
  try {
    await fs.access(filePath);
  } catch {
    throw new Error(`Missing required file: ${filePath}`);
  }
}

async function run() {
  const projectRoot = path.resolve(__dirname, '..');
  const siteUrl = (process.env.SITE_URL || 'http://localhost:3000').replace(/\/$/, '');
  const distDir = path.join(projectRoot, 'dist');
  const indexPath = path.join(distDir, 'index.html');
  const sitemapPath = path.join(distDir, 'sitemap.xml');
  const appPath = path.join(projectRoot, 'src', 'App.tsx');

  await ensureExists(indexPath);
  await ensureExists(sitemapPath);

  const indexHtml = await fs.readFile(indexPath, 'utf8');
  const appSource = await fs.readFile(appPath, 'utf8');
  const sitemapXml = await fs.readFile(sitemapPath, 'utf8');

  const indexChecks = [
    { label: 'root mount', pass: indexHtml.includes('<div id="root"></div>') },
    { label: 'built js asset reference', pass: /assets\/index-.*\.js/.test(indexHtml) },
    { label: 'built css asset reference', pass: /assets\/index-.*\.css/.test(indexHtml) },
  ];

  const routeChecks = [
    { label: 'home route', pass: appSource.includes('path="/"') },
    { label: 'platform route', pass: appSource.includes('path="/platform"') },
    { label: 'auth callback route', pass: appSource.includes('path="/auth/callback"') },
    { label: 'auth error route', pass: appSource.includes('path="/auth/error"') },
    { label: 'status route', pass: appSource.includes('path="/status"') },
    { label: 'diagnostics route', pass: appSource.includes('path="/diagnostics"') },
    { label: 'docs route', pass: appSource.includes('path="/docs"') },
    { label: 'ui checklist route', pass: appSource.includes('path="/qa/ui-checklist"') },
    { label: 'ui wiring route', pass: appSource.includes('path="/qa/ui-wiring"') },
    { label: 'risk copilot product route', pass: appSource.includes('path="/products/risk-copilot"') },
    { label: 'compliance engine product route', pass: appSource.includes('path="/products/compliance-engine"') },
    { label: 'threat intel product route', pass: appSource.includes('path="/products/threat-intel"') },
    { label: 'pricing route', pass: appSource.includes('path="/pricing"') },
    { label: 'about route', pass: appSource.includes('path="/about"') },
    { label: 'blog route', pass: appSource.includes('path="/blog"') },
    { label: 'privacy route', pass: appSource.includes('path="/legal/privacy"') },
    { label: 'terms route', pass: appSource.includes('path="/legal/terms"') },
    { label: 'cookie route', pass: appSource.includes('path="/legal/cookies"') },
  ];

  const expectedHome = `<loc>${siteUrl}</loc>`;
  const expectedPlatform = `<loc>${siteUrl}/platform</loc>`;
  const expectedAuthCallback = `<loc>${siteUrl}/auth/callback</loc>`;
  const expectedAuthError = `<loc>${siteUrl}/auth/error</loc>`;
  const expectedPrivacy = `<loc>${siteUrl}/legal/privacy</loc>`;
  const expectedTerms = `<loc>${siteUrl}/legal/terms</loc>`;
  const expectedCookies = `<loc>${siteUrl}/legal/cookies</loc>`;

  const sitemapChecks = [
    { label: 'home in sitemap', pass: sitemapXml.includes(expectedHome) },
    {
      label: 'platform in sitemap',
      pass: sitemapXml.includes(expectedPlatform),
    },
    {
      label: 'auth callback in sitemap',
      pass: sitemapXml.includes(expectedAuthCallback),
    },
    {
      label: 'auth error in sitemap',
      pass: sitemapXml.includes(expectedAuthError),
    },
    {
      label: 'privacy in sitemap',
      pass: sitemapXml.includes(expectedPrivacy),
    },
    {
      label: 'terms in sitemap',
      pass: sitemapXml.includes(expectedTerms),
    },
    {
      label: 'cookies in sitemap',
      pass: sitemapXml.includes(expectedCookies),
    },
  ];

  const checks = [...indexChecks, ...routeChecks, ...sitemapChecks];
  const failed = checks.filter(check => !check.pass);

  checks.forEach(check => {
    process.stdout.write(`${check.pass ? 'PASS' : 'FAIL'}: ${check.label}\n`);
  });

  if (failed.length) {
    throw new Error(`${failed.length} smoke checks failed.`);
  }

  process.stdout.write('Smoke checks passed.\n');
}

run().catch(error => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
