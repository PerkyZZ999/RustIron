// Lab bridge, PC side: every 15 s, asks the lab VM's executor for its
// read-only observation over the existing lab SSH access and replaces the
// local file atomically. It runs one fixed command and accepts only the
// observation schema, or the executor's exact EXECUTOR_NOT_ENROLLED answer
// (W347), which it saves as a refusal document; any other failure leaves the
// previous file, which then ages into "stale" in the console.
//
//   RUSTIRON_LAB_SSH=~/.config/rustiron-lab/ssh.sh bun scripts/lab-pull.ts .live/observation.json
import { mkdir, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import {
  type ExecutorRefusal,
  isExecutorRefusal,
  isMachine,
  isObservation,
  type Observation,
} from "../src/live";

const REMOTE = "/usr/local/libexec/rustiron-s02-lab/rustiron-s02-executor observe";
/** Unprivileged: the host status runs as the lab build user, not root. */
const REMOTE_HOST =
  "runuser -u rustiron-build -- /usr/local/libexec/rustiron-s02-lab-test/rustiron-control --host-status";
/** Host-local merge: journal observe + status + capped sample file. */
const REMOTE_LOCAL =
  "sh /usr/local/libexec/rustiron-s02-lab-test/observe-local /home/rustiron-build/rustiron-observe/observation.json";
const INTERVAL_MS = 15_000;
const TIMEOUT_MS = 10_000;

const ssh = process.env.RUSTIRON_LAB_SSH;
const target = process.argv[2];
if (!ssh || !target) {
  console.error("usage: RUSTIRON_LAB_SSH=PATH bun scripts/lab-pull.ts OUTPUT.json");
  process.exit(2);
}

/** W347: the executor's exact stderr line (exit 2) when the host has no enrolled policy. */
const NOT_ENROLLED_LINE = '{"scope":"s02_lab_executor","error":"EXECUTOR_NOT_ENROLLED"}';
const NOT_ENROLLED: ExecutorRefusal = {
  schema: "rustiron-executor-refusal/1",
  error: "EXECUTOR_NOT_ENROLLED",
};

class Refused extends Error {}

async function run(command: string): Promise<unknown> {
  const child = Bun.spawn([ssh as string, command], {
    stdout: "pipe",
    stderr: "pipe",
    timeout: TIMEOUT_MS,
  });
  const [text, errors, exit] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  // Only this one fixed line is recognised; any other stderr stays unread.
  if (exit === 2 && errors.trim() === NOT_ENROLLED_LINE) throw new Refused();
  if (exit !== 0) throw new Error(`ssh exited ${exit}`);
  return JSON.parse(text);
}

async function fallback(): Promise<unknown> {
  const observation = await run(REMOTE).catch((error: unknown) => {
    if (error instanceof Refused) return NOT_ENROLLED;
    throw error;
  });
  if (isExecutorRefusal(observation)) return observation;
  if (!isObservation(observation)) return null;
  const machine = await run(REMOTE_HOST).catch(() => null);
  return isMachine(machine) ? { ...observation, machine } : observation;
}

async function save(value: unknown): Promise<void> {
  await mkdir(dirname(target as string), { recursive: true, mode: 0o700 });
  const temporary = `${target}.tmp`;
  await writeFile(temporary, JSON.stringify(value), { mode: 0o600 });
  await rename(temporary, target as string);
}

function saved(value: Observation | ExecutorRefusal): string {
  if (isExecutorRefusal(value)) return "executor not enrolled";
  return value.machine ? "ok" : "ok (no host status)";
}

async function pull(): Promise<string> {
  const local = await run(REMOTE_LOCAL).catch(() => null);
  const merged = isObservation(local) ? local : await fallback();
  if (!isObservation(merged) && !isExecutorRefusal(merged)) return "output was not an observation";
  await save(merged);
  return saved(merged);
}

for (;;) {
  const result = await pull().catch(() => "pull failed");
  console.log(`${new Date().toISOString()} observation ${result}`);
  await Bun.sleep(INTERVAL_MS);
}
