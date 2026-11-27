// W730 (TOTP task 38): removes one Console account's second factor from the host
// shell. Run it as the Console service user; see Runbook 38.
//   RUSTIRON_CONSOLE_AUTH_DB=<path> bun scripts/reset-second-factor.ts <email>
import { Database } from "bun:sqlite";
import { existsSync } from "node:fs";

import { resetSecondFactor } from "../src/second-factor-reset";

const dbPath = process.env.RUSTIRON_CONSOLE_AUTH_DB?.trim();
const email = process.argv[2]?.trim();
if (!dbPath || !email || process.argv.length > 3) {
  console.error(
    "Usage: RUSTIRON_CONSOLE_AUTH_DB=<path to auth.sqlite> bun scripts/reset-second-factor.ts <email>",
  );
  process.exit(2);
}
// The path must name the running Console's database; the script never makes one.
if (!existsSync(dbPath)) {
  console.error(`No Console account database at ${dbPath}.`);
  process.exit(1);
}

const db = new Database(dbPath, { readwrite: true, create: false });
try {
  db.exec("PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;");
  const reset = resetSecondFactor(db, email);
  console.log(
    reset.removedFactor
      ? `Removed the second factor of ${reset.email} (${reset.role}) and ended ${reset.endedSessions} session(s).`
      : `${reset.email} (${reset.role}) had no second factor. Ended ${reset.endedSessions} session(s).`,
  );
  if (reset.role === "admin") {
    console.log("The account signs in with its password, then sets up a new second factor.");
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
} finally {
  db.close();
}
