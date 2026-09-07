import * as fs from 'fs';
import * as path from 'path';

/**
 * The scenarios are one ordered story; this file carries ids between spec
 * files (workspace id, credential id, the user code from `register`).
 */
const FILE = path.resolve(__dirname, '..', '..', '.state.json');

export type State = Record<string, any>;

export function readState(): State {
  try {
    return JSON.parse(fs.readFileSync(FILE, 'utf8'));
  } catch {
    return {};
  }
}

export function writeState(patch: State): State {
  const next = { ...readState(), ...patch };
  fs.writeFileSync(FILE, JSON.stringify(next, null, 2));
  return next;
}

export function need(key: string): any {
  const v = readState()[key];
  if (v === undefined || v === null || v === '') {
    throw new Error(
      `shared state is missing "${key}" — an earlier scenario did not complete`,
    );
  }
  return v;
}

/** Findings a new user would hit, accumulated across scenarios for REPORT.md. */
const FINDINGS = path.resolve(__dirname, '..', '..', '..', 'artifacts', 'findings.json');

export interface Finding {
  scenario: string;
  title: string;
  doc: string;
  detail: string;
  workaround?: string;
}

export function recordFinding(f: Finding): void {
  let all: Finding[] = [];
  try {
    all = JSON.parse(fs.readFileSync(FINDINGS, 'utf8'));
  } catch {
    /* first finding */
  }
  all.push(f);
  fs.mkdirSync(path.dirname(FINDINGS), { recursive: true });
  fs.writeFileSync(FINDINGS, JSON.stringify(all, null, 2));
  // Also surface it in the test log so the console run shows it.
  // eslint-disable-next-line no-console
  console.log(`\n  [DOC/PRODUCT GAP] ${f.scenario}: ${f.title}\n    doc: ${f.doc}\n    ${f.detail}\n`);
}
