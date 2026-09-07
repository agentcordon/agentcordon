#!/usr/bin/env node
/**
 * Summarise a Playwright JSON report so the harness's own tally distinguishes
 * the three outcomes a reader of REPORT.md actually cares about:
 *
 *   passed                  a real pass
 *   expected failure        a `test.fail()` test that failed, i.e. a defect
 *                           this run still reproduces
 *   unexpected pass         a `test.fail()` test that PASSED — the defect it
 *                           documents looks fixed; drop the test.fail()
 *   failed                  a real failure
 *
 * Playwright's own `stats.expected` lumps the first two together, which is how
 * "62 passed" ended up including tests that were asserting known defects.
 *
 *   node uat/summarize-results.js <results.json> [--json <out.json>]
 *
 * Test titles carry finding ids in brackets — `[D7]`, `[G3]` — so the tally
 * also reports which REPORT.md defect or gap each test covers.
 */

const fs = require('fs');

const args = process.argv.slice(2);
const input = args[0];
const jsonOutIdx = args.indexOf('--json');
const jsonOut = jsonOutIdx >= 0 ? args[jsonOutIdx + 1] : null;

if (!input || !fs.existsSync(input)) {
  console.error(`summarize-results: no results file at ${input || '<none>'}`);
  process.exit(2);
}

const report = JSON.parse(fs.readFileSync(input, 'utf8'));

/** Walk the nested suite tree and yield one record per test. */
function collect(suite, trail, out) {
  const title = [...trail, suite.title].filter(Boolean);
  for (const spec of suite.specs || []) {
    for (const t of spec.tests || []) {
      const results = t.results || [];
      const last = results[results.length - 1] || {};
      out.push({
        file: spec.file,
        line: spec.line,
        title: [...title, spec.title].join(' › '),
        expectedStatus: t.expectedStatus || 'passed',
        status: last.status || 'skipped',
        annotations: (t.annotations || []).map((a) => a.type),
        durationMs: last.duration || 0,
      });
    }
  }
  for (const child of suite.suites || []) collect(child, title, out);
}

const tests = [];
for (const suite of report.suites || []) collect(suite, [], tests);

const FINDING_RE = /\[([DG]\d+(?:[a-z])?|REVIEW-\d+)\]/g;
function findings(title) {
  return [...title.matchAll(FINDING_RE)].map((m) => m[1]);
}

const buckets = {
  passed: [],
  expectedFailure: [],
  unexpectedPass: [],
  failed: [],
  skipped: [],
};

for (const t of tests) {
  t.findings = findings(t.title);
  const wantFail = t.expectedStatus === 'failed';
  if (t.status === 'skipped') buckets.skipped.push(t);
  else if (wantFail && t.status === 'failed') buckets.expectedFailure.push(t);
  else if (wantFail && t.status === 'passed') buckets.unexpectedPass.push(t);
  else if (t.status === 'passed') buckets.passed.push(t);
  else buckets.failed.push(t);
}

const coverage = {};
for (const t of tests) {
  for (const f of t.findings) {
    coverage[f] = coverage[f] || { finding: f, tests: [] };
    coverage[f].tests.push({ title: t.title, status: t.status, expectedStatus: t.expectedStatus });
  }
}

const summary = {
  generated_at: new Date().toISOString(),
  totals: {
    passed: buckets.passed.length,
    expected_failures: buckets.expectedFailure.length,
    unexpected_passes: buckets.unexpectedPass.length,
    failed: buckets.failed.length,
    skipped: buckets.skipped.length,
    total: tests.length,
  },
  expected_failures: buckets.expectedFailure.map((t) => ({
    title: t.title,
    file: t.file,
    findings: t.findings,
  })),
  unexpected_passes: buckets.unexpectedPass.map((t) => ({
    title: t.title,
    file: t.file,
    findings: t.findings,
  })),
  failures: buckets.failed.map((t) => ({ title: t.title, file: t.file, findings: t.findings })),
  skipped: buckets.skipped.map((t) => ({ title: t.title, file: t.file, findings: t.findings })),
  finding_coverage: Object.values(coverage).sort((a, b) => a.finding.localeCompare(b.finding)),
};

if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify(summary, null, 2));

const t = summary.totals;
const line = (s) => console.log(s);
line('');
line(`  ${t.passed} passed`);
line(`  ${t.expected_failures} expected failure(s)  (test.fail: defects this run still reproduces)`);
line(`  ${t.unexpected_passes} unexpected pass(es)  (test.fail that PASSED: the defect looks fixed)`);
line(`  ${t.failed} failed`);
line(`  ${t.skipped} skipped`);
line(`  ${t.total} total`);

if (buckets.expectedFailure.length) {
  line('');
  line('  Expected failures (known-open defects):');
  for (const x of buckets.expectedFailure) {
    line(`    ${x.findings.length ? x.findings.join(',') : '(untagged)'}  ${x.title}`);
  }
}
if (buckets.unexpectedPass.length) {
  line('');
  line('  UNEXPECTED PASSES — remove the test.fail() and assert the fixed behaviour:');
  for (const x of buckets.unexpectedPass) {
    line(`    ${x.findings.length ? x.findings.join(',') : '(untagged)'}  ${x.title}`);
  }
}
if (buckets.failed.length) {
  line('');
  line('  Failures:');
  for (const x of buckets.failed) line(`    ${x.title}`);
}
if (buckets.skipped.length) {
  line('');
  line('  Skipped:');
  for (const x of buckets.skipped) line(`    ${x.title}`);
}
if (summary.finding_coverage.length) {
  line('');
  line('  REPORT.md findings covered by a test:');
  for (const c of summary.finding_coverage) {
    line(`    ${c.finding}: ${c.tests.length} test(s)`);
  }
}
line('');
