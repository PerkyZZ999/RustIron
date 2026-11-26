import { GlobalRegistrator } from "@happy-dom/global-registrator";

GlobalRegistrator.register();

// Tests run on fixture data: the console server reports no live source.
globalThis.fetch = (async () => Response.json({ source: "fixture" })) as unknown as typeof fetch;
