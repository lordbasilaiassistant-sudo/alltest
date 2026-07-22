// FIXTURE: clean code. The scanner MUST report ZERO findings here (>= low).
// This guards against false positives — a regression that starts flagging clean code
// fails this fixture.

import crypto from 'node:crypto';

/** Generate a cryptographically secure token. */
export function makeToken() {
  return crypto.randomBytes(32).toString('hex');
}

/** Parameterized query helper — no injection surface. */
export async function findUser(db, id) {
  return db.query({ sql: 'SELECT id, name FROM users WHERE id = ?', args: [id] });
}

export function greet(name) {
  return `Hello, ${name}`;
}
