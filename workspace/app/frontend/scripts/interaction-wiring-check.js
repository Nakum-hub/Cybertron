#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const currentFilePath = fileURLToPath(import.meta.url);
const rootDir = path.resolve(path.dirname(currentFilePath), '..');
const srcDir = path.resolve(rootDir, 'src');
const appPath = path.resolve(srcDir, 'App.tsx');

function readFile(filePath) {
  return fs.readFileSync(filePath, 'utf8');
}

function listFiles(dirPath) {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.resolve(dirPath, entry.name);
    if (entry.isDirectory()) {
      files.push(...listFiles(fullPath));
      continue;
    }
    if (entry.isFile() && /\.(tsx|ts)$/.test(entry.name)) {
      files.push(fullPath);
    }
  }
  return files;
}

function normalizeRoutePath(routePath) {
  const value = String(routePath || '').trim();
  if (!value || value === '/') {
    return '/';
  }
  return value.replace(/\/+$/, '');
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function routeToRegex(routePath) {
  if (routePath === '*') {
    return /^.*$/;
  }

  const segments = routePath.split('/').filter(Boolean);
  if (!segments.length) {
    return /^\/$/;
  }

  const rendered = segments
    .map(segment => {
      if (segment === '*') {
        return '.*';
      }
      if (segment.startsWith(':')) {
        return '[^/]+';
      }
      return escapeRegex(segment);
    })
    .join('/');

  return new RegExp(`^/${rendered}$`);
}

function collectRoutes(appSource) {
  const routePaths = [];
  const routeRegex = /<Route\s+path="([^"]+)"/g;
  let match = routeRegex.exec(appSource);
  while (match) {
    routePaths.push(match[1]);
    match = routeRegex.exec(appSource);
  }
  return routePaths;
}

function collectSectionIds(sourceFiles) {
  const ids = new Set();
  const idRegex = /\sid="([a-zA-Z0-9_-]+)"/g;
  for (const filePath of sourceFiles) {
    const source = readFile(filePath);
    let match = idRegex.exec(source);
    while (match) {
      ids.add(match[1]);
      match = idRegex.exec(source);
    }
  }
  return ids;
}

function collectTargets(sourceFiles) {
  const targets = [];
  const patterns = [
    { kind: 'to', regex: /\bto="([^"]+)"/g },
    { kind: 'href', regex: /\bhref="([^"]+)"/g },
    { kind: 'location.assign', regex: /window\.location\.assign\('([^']+)'\)/g },
    { kind: 'location.assign', regex: /window\.location\.assign\("([^"]+)"\)/g },
    { kind: 'location.assign', regex: /window\.location\.assign\(`([^`$]+)`\)/g },
  ];

  for (const filePath of sourceFiles) {
    const source = readFile(filePath);
    for (const pattern of patterns) {
      let match = pattern.regex.exec(source);
      while (match) {
        targets.push({
          filePath: path.relative(rootDir, filePath).replace(/\\/g, '/'),
          kind: pattern.kind,
          value: match[1],
        });
        match = pattern.regex.exec(source);
      }
    }
  }
  return targets;
}

function isExternalTarget(value) {
  return (
    value.startsWith('http://') ||
    value.startsWith('https://') ||
    value.startsWith('mailto:') ||
    value.startsWith('tel:') ||
    value.startsWith('javascript:')
  );
}

function hasMatchingRoute(pathname, routeMatchers) {
  for (const matcher of routeMatchers) {
    if (matcher.regex.test(pathname)) {
      return true;
    }
  }
  return false;
}

function main() {
  const appSource = readFile(appPath);
  const sourceFiles = listFiles(srcDir);
  const sectionIds = collectSectionIds(sourceFiles);
  const routePaths = collectRoutes(appSource);
  const routeMatchers = routePaths.map(routePath => ({
    routePath,
    regex: routeToRegex(routePath),
  }));
  const targets = collectTargets(sourceFiles);

  const failures = [];
  const checked = [];

  for (const target of targets) {
    const raw = String(target.value || '').trim();
    if (!raw) {
      continue;
    }
    if (isExternalTarget(raw)) {
      continue;
    }
    if (raw.startsWith('/api/')) {
      continue;
    }

    if (raw.startsWith('#')) {
      const id = raw.slice(1);
      checked.push(`${target.filePath} :: ${raw}`);
      if (!sectionIds.has(id)) {
        failures.push(`${target.filePath}: missing section id "${id}" for target "${raw}"`);
      }
      continue;
    }

    const url = new URL(raw, 'http://local.test');
    const pathname = normalizeRoutePath(url.pathname);
    const hash = (url.hash || '').replace(/^#/, '');
    checked.push(`${target.filePath} :: ${raw}`);

    if (!hasMatchingRoute(pathname, routeMatchers)) {
      failures.push(`${target.filePath}: no route matches "${raw}" (resolved path "${pathname}")`);
      continue;
    }

    if (hash && !sectionIds.has(hash)) {
      failures.push(`${target.filePath}: hash "${hash}" in "${raw}" has no matching section id`);
    }
  }

  process.stdout.write(`Checked targets: ${checked.length}\n`);
  process.stdout.write(`Registered routes: ${routePaths.length}\n`);
  if (failures.length === 0) {
    process.stdout.write('PASS: interaction targets map to valid routes/sections.\n');
    return;
  }

  process.stderr.write('FAIL: found unresolved interaction targets:\n');
  for (const failure of failures) {
    process.stderr.write(`- ${failure}\n`);
  }
  process.exitCode = 1;
}

main();
