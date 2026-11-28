import { GlobalRegistrator } from "@happy-dom/global-registrator";

// Bun's own fetch classes stay: Bun.serve needs native responses (auth-http.test.ts).
const { Request, Response, Headers } = globalThis;
GlobalRegistrator.register();
Object.assign(globalThis, { Request, Response, Headers });

// Tests run on fixture data: the console server reports no live source.
globalThis.fetch = (async () => Response.json({ source: "fixture" })) as unknown as typeof fetch;

// happy-dom's Web Animations rejects a canceled animation's `finished` promise
// unhandled (browsers mark it handled), which fails whichever test is running.
// Without `animate`, motion uses its frame-based engine instead.
for (const proto of [
  window.Element.prototype,
  window.HTMLElement.prototype,
  window.SVGElement.prototype,
]) {
  if (Object.hasOwn(proto, "animate")) Reflect.deleteProperty(proto, "animate");
}
