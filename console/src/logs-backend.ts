// W632 / W650: Strictly allowlisted, bounded, redacted read-only server logs
// endpoint (GET /api/host/logs). Never accepts arbitrary unit names or shell arguments,
// detects journald permission hints even on exit 0, and redacts credential-like patterns.
import { checkD090Request, jsonReply } from "./backend-server";

const ALLOWED_UNITS: Record<string, string> = {
  executor: "rustiron-executor.service",
  coordinator: "rustiron-coordinator.service",
  control: "rustiron-coordinator.service",
  admin: "rustiron-admin-helper.service",
  console: "rustiron-console.service",
  caddy: "rustiron-caddy.service",
  ols: "lshttpd.service",
  mariadb: "mariadb.service",
  postgresql: "postgresql-18.service",
  pdns: "pdns.service",
  postfix: "postfix.service",
  dovecot: "dovecot.service",
  sitecron: "rustiron-site-cron.service",
};

const MAX_LOG_STREAM_BYTES = 131_072;
const MAX_STDERR_BYTES = 8_192;

const SECRET_PATTERNS: [RegExp, string][] = [
  [
    /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/gi,
    "[REDACTED PRIVATE KEY]",
  ],
  [
    /((?:https?|mysql|mariadb|postgres(?:ql)?|redis|amqp|smtps?|imaps?):\/\/[^:\s/@]+:)[^@\s/]+@/gi,
    "$1[REDACTED]@",
  ],
  [
    /(password|passwd|secret|token|authorization|api[_-]?key|x-rustiron-csrf|set-cookie|cookie)\s*[:=]\s*\S+/gi,
    "$1=[REDACTED]",
  ],
  [/Bearer\s+[A-Za-z0-9._~+/-]+=*/gi, "Bearer [REDACTED]"],
  // W662: SQL statement form (PostgreSQL/MariaDB error and statement logs).
  [/(PASSWORD\s+)'[^']*'/gi, "$1'[REDACTED]'"],
];

function isAsciiLetter(code: number): boolean {
  return (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a);
}

function skipCsiSequence(raw: string, start: number): number {
  let i = start + 2;
  while (i < raw.length) {
    const code = raw.charCodeAt(i);
    i += 1;
    if (isAsciiLetter(code)) break;
  }
  return i;
}

function isPrintableChar(code: number): boolean {
  return (code >= 0x20 && code !== 0x7f) || code === 0x09;
}

function stripAnsiAndControl(raw: string): string {
  let out = "";
  let i = 0;
  while (i < raw.length) {
    const code = raw.charCodeAt(i);
    if (code === 0x1b && raw.charCodeAt(i + 1) === 0x5b) {
      i = skipCsiSequence(raw, i);
      continue;
    }
    if (isPrintableChar(code)) out += raw[i];
    i += 1;
  }
  return out;
}

export function redactLogLine(raw: string): string {
  let clean = stripAnsiAndControl(raw);
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    clean = clean.replace(pattern, replacement);
  }
  return clean.slice(0, 600);
}

export function allowedLogUnits() {
  return Object.entries(ALLOWED_UNITS).map(([key, unit]) => ({ key, unit }));
}

function clampLineCount(raw: string | null): number {
  const parsed = Number(raw ?? 60);
  if (!Number.isInteger(parsed) || parsed < 10 || parsed > 200) return 60;
  return parsed;
}

function parseJournalOutput(stdout: string): string[] {
  return stdout
    .split("\n")
    .map((line) => line.trimEnd())
    .filter(
      (line) =>
        line.length > 0 && !line.startsWith("-- No entries") && !line.startsWith("-- Boot "),
    )
    .map(redactLogLine);
}

function isJournalPermissionHint(stderr: string): boolean {
  const lower = stderr.toLowerCase();
  return (
    lower.includes("not seeing messages from other users") ||
    lower.includes("systemd-journal") ||
    lower.includes("permission denied")
  );
}

async function readBoundedText(
  stream: ReadableStream<Uint8Array>,
  maxBytes: number,
): Promise<{ text: string; truncated: boolean }> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done || !value) break;
      const remaining = maxBytes - total;
      if (remaining <= 0) {
        truncated = true;
        await reader.cancel().catch(() => {});
        break;
      }
      const slice = value.byteLength > remaining ? value.subarray(0, remaining) : value;
      chunks.push(slice);
      total += slice.byteLength;
      if (value.byteLength > remaining) {
        truncated = true;
        await reader.cancel().catch(() => {});
        break;
      }
    }
  } finally {
    reader.releaseLock();
  }
  return { text: Buffer.concat(chunks, total).toString("utf8"), truncated };
}

async function readJournalUnit(unitKey: string, unit: string, lines: number): Promise<Response> {
  const fetchedAt = Date.now();
  try {
    const proc = Bun.spawn(
      ["journalctl", "-u", unit, "-n", String(lines), "--no-pager", "-o", "short-iso"],
      { stdout: "pipe", stderr: "pipe", timeout: 4_000 },
    );
    const [{ text: stdout, truncated }, { text: stderr }, exit] = await Promise.all([
      readBoundedText(proc.stdout, MAX_LOG_STREAM_BYTES),
      readBoundedText(proc.stderr, MAX_STDERR_BYTES),
      proc.exited,
    ]);
    if (exit !== 0 && !truncated) {
      return jsonReply(200, {
        unitKey,
        unit,
        available: false,
        fetchedAt,
        reason: `journalctl returned exit ${exit} (the Console service user may need SupplementaryGroups=systemd-journal).`,
        lines: [],
      });
    }
    const parsed = parseJournalOutput(stdout);
    if (parsed.length === 0 && isJournalPermissionHint(stderr)) {
      return jsonReply(200, {
        unitKey,
        unit,
        available: false,
        fetchedAt,
        reason:
          "The Console service user lacks read access to system journald logs. Add SupplementaryGroups=systemd-journal to rustiron-console.service and restart it.",
        lines: [],
      });
    }
    return jsonReply(200, {
      unitKey,
      unit,
      available: parsed.length > 0,
      truncated,
      fetchedAt,
      reason: parsed.length > 0 ? null : `No recent journald entries found for ${unit}.`,
      lines: parsed,
    });
  } catch {
    return jsonReply(200, {
      unitKey,
      unit,
      available: false,
      fetchedAt,
      reason: "journalctl is unavailable on this host.",
      lines: [],
    });
  }
}

export function createHostLogsHandler(options: {
  getAllowedHosts: () => ReadonlySet<string>;
  disableSpawn?: boolean;
}) {
  return async (req: Request): Promise<Response> => {
    const guard = checkD090Request(req, options.getAllowedHosts());
    if (guard) return guard;
    const url = new URL(req.url);
    const unitKey = (url.searchParams.get("unit") ?? "executor").toLowerCase();
    const unit = ALLOWED_UNITS[unitKey];
    if (!unit) {
      return jsonReply(400, {
        error: "UNKNOWN_UNIT",
        allowed: Object.keys(ALLOWED_UNITS),
      });
    }
    const lines = clampLineCount(url.searchParams.get("lines"));
    if (options.disableSpawn) {
      return jsonReply(200, {
        unitKey,
        unit,
        available: false,
        fetchedAt: Date.now(),
        reason: "Local journald inspection is disabled in this preview environment.",
        lines: [],
      });
    }
    return readJournalUnit(unitKey, unit, lines);
  };
}
