// ── PDF Report Generator ─────────────────────────────────────────────────────
// Produces multi-page, branded, enterprise-grade PDF reports using raw PDF 1.4
// primitives. No external dependencies.
//
// Built-in Type1 fonts used (available in every PDF reader):
//   F1 = Helvetica          (body text)
//   F2 = Helvetica-Bold     (headings, labels, table headers)
//   F3 = Courier            (monospace data, IDs)
// ─────────────────────────────────────────────────────────────────────────────

const SEVERITY_COLORS = {
  critical: [0.82, 0.14, 0.11],
  high: [0.88, 0.42, 0.08],
  medium: [0.78, 0.62, 0.08],
  low: [0.18, 0.62, 0.32],
};

const C = {
  title: [0.06, 0.10, 0.20],
  heading: [0.08, 0.20, 0.40],
  body: [0.14, 0.14, 0.17],
  muted: [0.42, 0.45, 0.50],
  accent: [0.04, 0.58, 0.74],
  white: [1, 1, 1],
  rowAlt: [0.95, 0.96, 0.97],
  tableHead: [0.10, 0.18, 0.32],
};

const PAGE_W = 612;
const PAGE_H = 792;
const MARGIN = { top: 58, right: 48, bottom: 52, left: 48 };
const CONTENT_W = PAGE_W - MARGIN.left - MARGIN.right;

// ── Utilities ────────────────────────────────────────────────────────────────

function esc(text) {
  return String(text || '')
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)')
    .replace(/\r?\n/g, ' ');
}

function formatDate(value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) {
    return String(value || '');
  }
  const pad = n => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
}

function approxTextWidth(text, fontSize, bold) {
  const factor = bold ? 0.56 : 0.52;
  return String(text || '').length * fontSize * factor;
}

function wrapText(text, fontSize, bold, maxWidth) {
  if (!maxWidth) maxWidth = CONTENT_W;
  const charW = fontSize * (bold ? 0.56 : 0.52);
  const maxChars = Math.max(10, Math.floor(maxWidth / charW));
  const words = String(text || '').split(/\s+/).filter(Boolean);
  const lines = [];
  let current = '';

  for (const word of words) {
    const test = current ? `${current} ${word}` : word;
    if (test.length > maxChars && current) {
      lines.push(current);
      current = word.length > maxChars ? word.slice(0, maxChars) : word;
    } else {
      current = test;
    }
  }
  if (current) lines.push(current);
  if (lines.length === 0) lines.push('');
  return lines;
}

function truncate(text, max) {
  const s = String(text || '');
  return s.length > max ? s.slice(0, max - 3) + '...' : s;
}

// ── PdfWriter ────────────────────────────────────────────────────────────────

class PdfWriter {
  constructor(options = {}) {
    this.reportTitle = options.title || 'Report';
    this.reportSubtitle = options.subtitle || '';
    this.tenant = options.tenant || 'global';
    this.generatedAt = options.generatedAt || new Date().toISOString();
    this.pages = [];
    this.ops = null;
    this.y = 0;
    this.pageNum = 0;
  }

  // ── Page lifecycle ──

  newPage() {
    this.ops = [];
    this.pages.push(this.ops);
    this.pageNum += 1;
    this.y = PAGE_H - MARGIN.top;
    this._pageHeader();
    this.y -= 8;
  }

  ensureSpace(needed) {
    if (this.y - needed < MARGIN.bottom + 18) {
      this.newPage();
    }
  }

  get contentBottom() {
    return MARGIN.bottom + 18;
  }

  // ── Page chrome ──

  _pageHeader() {
    const o = this.ops;
    // Brand
    o.push('BT', '/F2 8.5 Tf', `${C.accent.join(' ')} rg`);
    o.push(`${MARGIN.left} ${this.y} Td`, '(CYBERTRON) Tj', 'ET');
    // Report type right-aligned
    const label = esc(this.reportTitle);
    const labelX = PAGE_W - MARGIN.right - approxTextWidth(label, 7, false);
    o.push('BT', '/F1 7 Tf', `${C.muted.join(' ')} rg`);
    o.push(`${labelX} ${this.y} Td`, `(${label}) Tj`, 'ET');
    this.y -= 9;
    // Accent line
    o.push(`${C.accent.join(' ')} RG`, '0.6 w');
    o.push(`${MARGIN.left} ${this.y} m ${PAGE_W - MARGIN.right} ${this.y} l S`);
    this.y -= 4;
  }

  _pageFooter(ops, num, total) {
    const fy = MARGIN.bottom - 18;
    // Separator
    ops.push(`${C.muted.join(' ')} RG`, '0.2 w');
    ops.push(`${MARGIN.left} ${fy + 11} m ${PAGE_W - MARGIN.right} ${fy + 11} l S`);
    // Left: confidential + tenant
    ops.push('BT', '/F1 6 Tf', `${C.muted.join(' ')} rg`);
    ops.push(`${MARGIN.left} ${fy} Td`);
    ops.push(`(CONFIDENTIAL  \\267  ${esc(this.tenant)}) Tj`, 'ET');
    // Center: page
    const pg = `${num} / ${total}`;
    const pgX = PAGE_W / 2 - approxTextWidth(pg, 6, false) / 2;
    ops.push('BT', '/F1 6 Tf', `${C.muted.join(' ')} rg`);
    ops.push(`${pgX} ${fy} Td`, `(${pg}) Tj`, 'ET');
    // Right: date
    const ds = esc(formatDate(this.generatedAt));
    const dsX = PAGE_W - MARGIN.right - approxTextWidth(ds, 6, false);
    ops.push('BT', '/F1 6 Tf', `${C.muted.join(' ')} rg`);
    ops.push(`${dsX} ${fy} Td`, `(${ds}) Tj`, 'ET');
  }

  // ── Cover page ──

  coverPage() {
    this.newPage();
    // Remove default header for cover
    this.ops.length = 0;

    const cx = MARGIN.left;
    const o = this.ops;

    // Top accent bar
    o.push(`${C.accent.join(' ')} rg`);
    o.push(`0 ${PAGE_H - 6} ${PAGE_W} 6 re f`);

    // Brand
    const brandY = PAGE_H - 80;
    o.push('BT', '/F2 11 Tf', `${C.accent.join(' ')} rg`);
    o.push(`${cx} ${brandY} Td`, '(CYBERTRON) Tj', 'ET');

    // Accent sidebar
    const titleBaseY = PAGE_H / 2 + 50;
    o.push(`${C.accent.join(' ')} rg`);
    o.push(`${cx} ${titleBaseY + 8} 3.5 -90 re f`);

    // Title lines
    let ty = titleBaseY;
    const titleLines = wrapText(this.reportTitle, 24, true, CONTENT_W - 20);
    for (const line of titleLines) {
      o.push('BT', '/F2 24 Tf', `${C.title.join(' ')} rg`);
      o.push(`${cx + 14} ${ty} Td`, `(${esc(line)}) Tj`, 'ET');
      ty -= 30;
    }
    ty -= 6;

    // Subtitle
    if (this.reportSubtitle) {
      o.push('BT', '/F1 11 Tf', `${C.muted.join(' ')} rg`);
      o.push(`${cx + 14} ${ty} Td`, `(${esc(this.reportSubtitle)}) Tj`, 'ET');
      ty -= 22;
    }

    // Metadata
    const metaLine = `Tenant: ${this.tenant}  \\267  Generated: ${formatDate(this.generatedAt)}`;
    o.push('BT', '/F1 9 Tf', `${C.muted.join(' ')} rg`);
    o.push(`${cx + 14} ${ty} Td`, `(${esc(metaLine)}) Tj`, 'ET');

    // Bottom accent bar
    o.push(`${C.accent.join(' ')} rg`);
    o.push(`0 0 ${PAGE_W} 4 re f`);

    this.y = MARGIN.bottom;
  }

  // ── High-level drawing ──

  sectionTitle(text) {
    this.ensureSpace(32);
    this.y -= 14;
    this.ops.push('BT', '/F2 13 Tf', `${C.heading.join(' ')} rg`);
    this.ops.push(`${MARGIN.left} ${this.y} Td`, `(${esc(text)}) Tj`, 'ET');
    this.y -= 5;
    this.ops.push(`${C.accent.join(' ')} RG`, '0.5 w');
    this.ops.push(`${MARGIN.left} ${this.y} m ${MARGIN.left + 130} ${this.y} l S`);
    this.y -= 14;
  }

  heading(text) {
    this.ensureSpace(24);
    this.y -= 8;
    this.ops.push('BT', '/F2 10.5 Tf', `${C.heading.join(' ')} rg`);
    this.ops.push(`${MARGIN.left} ${this.y} Td`, `(${esc(text)}) Tj`, 'ET');
    this.y -= 15;
  }

  body(text, options = {}) {
    const sz = options.fontSize || 9.5;
    const bold = Boolean(options.bold);
    const color = options.color || C.body;
    const indent = options.indent || 0;
    const maxW = CONTENT_W - indent;
    const lh = Math.ceil(sz * 1.45);
    const font = bold ? 'F2' : (options.mono ? 'F3' : 'F1');
    const lines = wrapText(text, sz, bold, maxW);

    this.ensureSpace(lh * Math.min(lines.length, 2));
    for (const line of lines) {
      if (this.y - lh < this.contentBottom) this.newPage();
      this.ops.push('BT', `/${font} ${sz} Tf`, `${color.join(' ')} rg`);
      this.ops.push(`${MARGIN.left + indent} ${this.y} Td`);
      this.ops.push(`(${esc(line)}) Tj`, 'ET');
      this.y -= lh;
    }
  }

  bullet(text, options = {}) {
    const indent = options.indent || 14;
    const bulletColor = options.bulletColor || C.accent;
    this.ensureSpace(16);
    // Square bullet
    this.ops.push(`${bulletColor.join(' ')} rg`);
    this.ops.push(`${MARGIN.left + indent - 9} ${this.y + 2} 3.5 3.5 re f`);
    this.body(text, { ...options, indent });
  }

  numberedItem(num, text, options = {}) {
    const indent = options.indent || 18;
    this.ensureSpace(16);
    this.ops.push('BT', '/F2 8.5 Tf', `${C.accent.join(' ')} rg`);
    this.ops.push(`${MARGIN.left + indent - 16} ${this.y} Td`);
    this.ops.push(`(${num}.) Tj`, 'ET');
    this.body(text, { ...options, indent });
  }

  metric(label, value, options = {}) {
    this.ensureSpace(17);
    const indent = options.indent || 0;
    const labelW = options.labelWidth || 190;
    // Label
    this.ops.push('BT', '/F1 9 Tf', `${C.muted.join(' ')} rg`);
    this.ops.push(`${MARGIN.left + indent} ${this.y} Td`, `(${esc(label)}) Tj`, 'ET');
    // Value
    const vc = options.valueColor || C.body;
    this.ops.push('BT', `/${options.bold ? 'F2' : 'F1'} ${options.valueFontSize || 10} Tf`);
    this.ops.push(`${vc.join(' ')} rg`);
    this.ops.push(`${MARGIN.left + indent + labelW} ${this.y} Td`);
    this.ops.push(`(${esc(String(value))}) Tj`, 'ET');
    this.y -= 16;
  }

  gap(pts) {
    this.y -= pts;
  }

  hr() {
    this.ensureSpace(12);
    this.y -= 5;
    this.ops.push(`${C.muted.join(' ')} RG`, '0.2 w');
    this.ops.push(`${MARGIN.left} ${this.y} m ${PAGE_W - MARGIN.right} ${this.y} l S`);
    this.y -= 8;
  }

  // ── Table ──

  table(headers, rows, options = {}) {
    const colWidths = options.colWidths || headers.map(() => Math.floor(CONTENT_W / headers.length));
    const rowH = options.rowHeight || 16;
    const fontSize = options.fontSize || 8;

    const drawHeaderRow = () => {
      let x = MARGIN.left;
      this.ops.push(`${C.tableHead.join(' ')} rg`);
      this.ops.push(`${MARGIN.left} ${this.y - 3} ${CONTENT_W} ${rowH} re f`);
      for (let i = 0; i < headers.length; i++) {
        this.ops.push('BT', `/F2 ${fontSize} Tf`, `${C.white.join(' ')} rg`);
        this.ops.push(`${x + 5} ${this.y} Td`);
        this.ops.push(`(${esc(headers[i])}) Tj`, 'ET');
        x += colWidths[i];
      }
      this.y -= rowH;
    };

    this.ensureSpace(rowH * 3);
    this.y -= 4;
    drawHeaderRow();

    let alt = false;
    for (const row of rows) {
      if (this.y - rowH < this.contentBottom) {
        this.newPage();
        this.y -= 4;
        drawHeaderRow();
        alt = false;
      }

      if (alt) {
        this.ops.push(`${C.rowAlt.join(' ')} rg`);
        this.ops.push(`${MARGIN.left} ${this.y - 3} ${CONTENT_W} ${rowH} re f`);
      }

      let x = MARGIN.left;
      for (let i = 0; i < headers.length; i++) {
        const cell = row[i] || {};
        const cellText = typeof cell === 'string' ? cell : String(cell.text ?? '');
        const cellColor = (typeof cell === 'object' && cell.color) ? cell.color : C.body;
        const cellBold = (typeof cell === 'object' && cell.bold) || false;
        const cellMono = (typeof cell === 'object' && cell.mono) || false;
        const font = cellBold ? 'F2' : (cellMono ? 'F3' : 'F1');

        const maxChars = Math.max(4, Math.floor(colWidths[i] / (fontSize * 0.52)) - 2);
        const display = truncate(cellText, maxChars);

        this.ops.push('BT', `/${font} ${fontSize} Tf`, `${cellColor.join(' ')} rg`);
        this.ops.push(`${x + 5} ${this.y} Td`);
        this.ops.push(`(${esc(display)}) Tj`, 'ET');
        x += colWidths[i];
      }

      this.y -= rowH;
      alt = !alt;
    }
    this.y -= 4;
  }

  // ── Build final PDF ──

  toBuffer() {
    const totalPages = this.pages.length;
    for (let i = 0; i < totalPages; i++) {
      this._pageFooter(this.pages[i], i + 1, totalPages);
    }

    const objects = [];
    // 1: Catalog
    objects.push('<< /Type /Catalog /Pages 2 0 R >>');
    // 2: Pages (placeholder)
    objects.push(null);
    // 3: Helvetica
    objects.push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
    // 4: Helvetica-Bold
    objects.push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
    // 5: Courier
    objects.push('<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>');

    const fontDict = '/F1 3 0 R /F2 4 0 R /F3 5 0 R';
    const pageObjNums = [];

    for (let i = 0; i < totalPages; i++) {
      const streamBody = this.pages[i].join('\n');
      const streamLen = Buffer.byteLength(streamBody, 'utf8');

      // Content stream
      const csIdx = objects.length;
      objects.push(`<< /Length ${streamLen} >>\nstream\n${streamBody}\nendstream`);

      // Page object
      const pgIdx = objects.length;
      pageObjNums.push(pgIdx + 1);
      objects.push(
        `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] ` +
        `/Resources << /Font << ${fontDict} >> >> /Contents ${csIdx + 1} 0 R >>`
      );
    }

    // Fill Pages object
    const kids = pageObjNums.map(n => `${n} 0 R`).join(' ');
    objects[1] = `<< /Type /Pages /Kids [${kids}] /Count ${totalPages} >>`;

    // Assemble PDF
    let pdf = '%PDF-1.4\n%\xE2\xE3\xCF\xD3\n';
    const offsets = [];
    for (let i = 0; i < objects.length; i++) {
      offsets.push(Buffer.byteLength(pdf, 'utf8'));
      pdf += `${i + 1} 0 obj\n${objects[i]}\nendobj\n`;
    }

    const xrefOff = Buffer.byteLength(pdf, 'utf8');
    pdf += `xref\n0 ${objects.length + 1}\n`;
    pdf += '0000000000 65535 f \n';
    for (const off of offsets) {
      pdf += `${String(off).padStart(10, '0')} 00000 n \n`;
    }
    pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\n`;
    pdf += `startxref\n${xrefOff}\n%%EOF\n`;

    return Buffer.from(pdf, 'utf8');
  }
}

// ── Risk Report ──────────────────────────────────────────────────────────────

function generateRiskReportPdf(payload = {}) {
  const portfolio = payload.portfolio || {};
  const findings = Array.isArray(payload.findings) ? payload.findings : [];
  const mitigations = Array.isArray(payload.mitigations) ? payload.mitigations : [];
  const aiExplanation = payload.aiExplanation || null;

  const pdf = new PdfWriter({
    title: 'Risk Copilot Board Report',
    subtitle: 'AI-Assisted Cybersecurity Risk Assessment',
    tenant: payload.tenant,
    generatedAt: payload.generatedAt,
  });

  // ── Cover ──
  pdf.coverPage();

  // ── Executive Summary ──
  pdf.newPage();
  pdf.sectionTitle('Executive Summary');

  const totalFindings = Number(portfolio.totalFindings || findings.length || 0);
  const criticalCount = Number(portfolio.critical || 0);
  const highCount = Number(portfolio.high || 0);
  const mediumCount = Number(portfolio.medium || 0);
  const lowCount = Number(portfolio.low || 0);
  const avgScore = Number(portfolio.averageScore || 0).toFixed(2);
  const highestScore = Number(portfolio.highestScore || 0).toFixed(2);

  pdf.metric('Total Findings', totalFindings, { bold: true, valueFontSize: 12 });
  pdf.gap(2);

  // Severity breakdown with colors
  pdf.metric('Critical', criticalCount, { valueColor: SEVERITY_COLORS.critical, bold: true });
  pdf.metric('High', highCount, { valueColor: SEVERITY_COLORS.high, bold: true });
  pdf.metric('Medium', mediumCount, { valueColor: SEVERITY_COLORS.medium });
  pdf.metric('Low', lowCount, { valueColor: SEVERITY_COLORS.low });
  pdf.gap(4);
  pdf.metric('Average Risk Score', avgScore);
  pdf.metric('Highest Risk Score', highestScore, {
    valueColor: Number(highestScore) >= 70 ? SEVERITY_COLORS.critical : C.body,
    bold: Number(highestScore) >= 70,
  });

  // ── AI Risk Analysis ──
  if (aiExplanation?.explanation || mitigations.length > 0) {
    pdf.sectionTitle('AI Risk Analysis');

    if (aiExplanation?.explanation) {
      pdf.heading('Risk Posture Assessment');
      // Split explanation into paragraphs on newlines
      const paragraphs = String(aiExplanation.explanation).split(/\n+/).filter(Boolean);
      for (const para of paragraphs) {
        const trimmed = para.trim();
        if (!trimmed) continue;
        // Detect bullet points
        if (/^[-\u2022*]\s/.test(trimmed)) {
          pdf.bullet(trimmed.replace(/^[-\u2022*]\s*/, ''));
        } else {
          pdf.body(trimmed);
          pdf.gap(3);
        }
      }

      if (aiExplanation.provider) {
        pdf.gap(4);
        pdf.body(
          `Analysis by: ${aiExplanation.provider}${aiExplanation.model ? ' / ' + aiExplanation.model : ''}`,
          { fontSize: 7.5, color: C.muted }
        );
      }
    }
  }

  // ── Mitigation Plan ──
  if (mitigations.length > 0) {
    pdf.sectionTitle('Prioritized Mitigation Plan');
    for (let i = 0; i < Math.min(mitigations.length, 15); i++) {
      pdf.numberedItem(i + 1, mitigations[i]);
    }
  } else {
    pdf.sectionTitle('Mitigation Plan');
    pdf.body('No findings require mitigation at this time. Maintain log ingestion and patch management cadence.', {
      color: C.muted,
    });
  }

  // ── Risk Findings Heatmap ──
  if (findings.length > 0) {
    pdf.sectionTitle('Risk Findings Heatmap');
    pdf.body(`Showing top ${Math.min(findings.length, 50)} findings by severity and score.`, {
      fontSize: 8, color: C.muted,
    });
    pdf.gap(6);

    const tableRows = findings.slice(0, 50).map(f => [
      { text: String(f.severity || 'n/a').toUpperCase(), color: SEVERITY_COLORS[f.severity] || C.body, bold: true },
      { text: Number(f.score || 0).toFixed(1) },
      { text: f.assetId || 'n/a', mono: true },
      { text: f.category || 'general' },
      { text: f.details?.title || 'Untitled' },
    ]);

    pdf.table(
      ['SEVERITY', 'SCORE', 'ASSET ID', 'CATEGORY', 'TITLE'],
      tableRows,
      { colWidths: [70, 48, 120, 90, 188] }
    );
  } else {
    pdf.sectionTitle('Risk Findings');
    pdf.body('No active risk findings. Continue daily log ingestion to populate findings.', { color: C.muted });
  }

  return pdf.toBuffer();
}

// ── Compliance Audit Package ─────────────────────────────────────────────────

function generateAuditPackagePdf(payload = {}) {
  const controls = Array.isArray(payload.controls) ? payload.controls : [];
  const evidence = Array.isArray(payload.evidence) ? payload.evidence : [];
  const policies = Array.isArray(payload.policies) ? payload.policies : [];

  const pdf = new PdfWriter({
    title: 'SOC2 Compliance Audit Package',
    subtitle: 'Cybertron Compliance Engine',
    tenant: payload.tenant,
    generatedAt: payload.generatedAt,
  });

  // ── Cover ──
  pdf.coverPage();

  // ── Readiness Summary ──
  pdf.newPage();
  pdf.sectionTitle('Readiness Summary');

  // Calculate status counts
  const statusCounts = { implemented: 0, validated: 0, in_progress: 0, not_started: 0, not_applicable: 0 };
  for (const c of controls) {
    const s = String(c.status || 'not_started').toLowerCase().replace(/\s+/g, '_');
    if (s in statusCounts) statusCounts[s] += 1;
    else statusCounts.not_started += 1;
  }
  const total = controls.length || 1;
  const readiness = Math.round(((statusCounts.implemented + statusCounts.validated) / total) * 100);

  pdf.metric('Total Controls', controls.length, { bold: true, valueFontSize: 12 });
  pdf.metric('Readiness Score', `${readiness}%`, {
    bold: true,
    valueFontSize: 12,
    valueColor: readiness >= 80 ? SEVERITY_COLORS.low : readiness >= 50 ? SEVERITY_COLORS.medium : SEVERITY_COLORS.critical,
  });
  pdf.gap(4);
  pdf.metric('Validated', statusCounts.validated, { valueColor: SEVERITY_COLORS.low });
  pdf.metric('Implemented', statusCounts.implemented, { valueColor: [0.16, 0.55, 0.70] });
  pdf.metric('In Progress', statusCounts.in_progress, { valueColor: SEVERITY_COLORS.medium });
  pdf.metric('Not Started', statusCounts.not_started, { valueColor: SEVERITY_COLORS.critical });
  pdf.metric('Not Applicable', statusCounts.not_applicable, { valueColor: C.muted });
  pdf.gap(4);
  pdf.metric('Evidence Files', evidence.length);
  pdf.metric('Policy Documents', policies.length);

  // ── Control Status ──
  if (controls.length > 0) {
    pdf.sectionTitle('Control Status');

    const STATUS_COLORS = {
      validated: SEVERITY_COLORS.low,
      implemented: [0.16, 0.55, 0.70],
      in_progress: SEVERITY_COLORS.medium,
      not_started: SEVERITY_COLORS.critical,
      not_applicable: C.muted,
    };

    const controlRows = controls.slice(0, 80).map(c => {
      const status = String(c.status || 'not_started').toLowerCase().replace(/\s+/g, '_');
      return [
        { text: c.controlId || 'n/a', mono: true, bold: true },
        { text: status.replace(/_/g, ' ').toUpperCase(), color: STATUS_COLORS[status] || C.body, bold: true },
        { text: String(Number(c.evidenceCount || 0)) },
        { text: c.description || '' },
      ];
    });

    pdf.table(
      ['CONTROL ID', 'STATUS', 'EVIDENCE', 'DESCRIPTION'],
      controlRows,
      { colWidths: [90, 95, 65, 266] }
    );
  }

  // ── Evidence Manifest ──
  if (evidence.length > 0) {
    pdf.sectionTitle('Evidence Manifest');

    const evidenceRows = evidence.slice(0, 60).map(e => [
      { text: e.controlId || 'n/a', mono: true },
      { text: e.fileName || 'unnamed' },
      { text: e.mimeType || 'unknown' },
      { text: formatFileSize(Number(e.sizeBytes || 0)) },
    ]);

    pdf.table(
      ['CONTROL ID', 'FILE NAME', 'MIME TYPE', 'SIZE'],
      evidenceRows,
      { colWidths: [90, 220, 110, 96] }
    );
  }

  // ── Policies ──
  if (policies.length > 0) {
    pdf.sectionTitle('Policy Documents');

    const policyRows = policies.slice(0, 40).map(p => [
      { text: p.policyKey || 'n/a', mono: true, bold: true },
      { text: formatDate(p.createdAt) },
      { text: p.provider || 'manual' },
    ]);

    pdf.table(
      ['POLICY KEY', 'CREATED', 'GENERATED BY'],
      policyRows,
      { colWidths: [220, 170, 126] }
    );
  }

  return pdf.toBuffer();
}

function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

module.exports = {
  generateRiskReportPdf,
  generateAuditPackagePdf,
};
