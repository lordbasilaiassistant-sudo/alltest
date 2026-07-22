// FIXTURE: dangerous JS patterns. Each PLANT must be caught by static/dangerous-js.

function run(userInput, db) {
  // PLANT: eval-use (high)
  const x = eval(userInput);

  // PLANT: child-process-concat (critical)
  require('child_process').execSync('ls ' + userInput);

  // PLANT: sql-concat (high) — real string concatenation into a query
  const q = "SELECT id FROM users WHERE name = '" + userInput + "'";
  db.query(q);

  // PLANT: disable-tls-verify (high)
  const opts = { rejectUnauthorized: false };

  // NOT a finding: parameterized query with bound-param arithmetic (skip)
  db.query({ sql: `UPDATE t SET total = ? + amount WHERE id = ?`, args: [x, 1] });

  // NOT a finding: safe placeholder IN-list
  const ph = '?,?,?';
  db.query({ sql: `SELECT * FROM u WHERE id IN (${ph})`, args: [1, 2, 3] });

  return { x, opts };
}

module.exports = { run };
