import * as fs from 'fs';
import * as path from 'path';

/**
 * The shipped documentation, read from the worktree the images were built
 * from.
 *
 * Several scenarios exist to check a promise the docs make. Asserting that
 * promise against a string literal copied into the test proves nothing — the
 * test and the doc can drift apart silently, which is how "hard-coded doc
 * facts asserted against themselves" got onto the review list. Reading the
 * real file means the assertion goes red when the doc changes, which is the
 * event worth catching.
 */
const ROOT = path.resolve(__dirname, '..', '..', '..', '..');

export function readDoc(relativePath: string): string {
  return fs.readFileSync(path.join(ROOT, relativePath), 'utf8');
}
