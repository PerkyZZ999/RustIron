import { GlobalRegistrator } from "@happy-dom/global-registrator";

// Bun's own fetch classes stay: Bun.serve needs native responses (auth-http.test.ts).
const { Request, Response, Headers } = globalThis;
GlobalRegistrator.register();
Object.assign(globalThis, { Request, Response, Headers });

// Tests run on fixture data: the console server reports no live source.
globalThis.fetch = (async () => Response.json({ source: "fixture" })) as unknown as typeof fetch;
