// W730 (TOTP task 38): the host-shell way back in for an account that lost both its
// authenticator app and its recovery codes. Runbook 38 describes the command.
import type { Database } from "bun:sqlite";

export type SecondFactorReset = {
  email: string;
  role: string;
  /** False when the account had no second factor to remove. */
  removedFactor: boolean;
  endedSessions: number;
};

/**
 * Removes one account's second factor and ends its sessions, in one transaction.
 * The next sign-in takes the password only; an Admin then meets the required
 * setup again (W729). Removing the `twoFactor` row also clears the plugin's
 * lock after repeated wrong codes. Throws for an unknown email.
 */
export function resetSecondFactor(db: Database, email: string): SecondFactorReset {
  const target = email.trim().toLowerCase();
  const run = db.transaction(() => {
    const user = db.query("SELECT id, role FROM user WHERE lower(email) = ?").get(target) as {
      id: string;
      role: string | null;
    } | null;
    if (!user) throw new Error(`No Console account has the email ${target}.`);
    const factor = db.query("DELETE FROM twoFactor WHERE userId = ?").run(user.id);
    db.query("UPDATE user SET twoFactorEnabled = 0 WHERE id = ?").run(user.id);
    const sessions = db.query("DELETE FROM session WHERE userId = ?").run(user.id);
    return {
      email: target,
      role: user.role ?? "viewer",
      removedFactor: factor.changes > 0,
      endedSessions: sessions.changes,
    };
  });
  return run.immediate();
}
