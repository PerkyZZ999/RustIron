# Serve a local service through a proxy site

Use a proxy site to serve one hostname through OpenLiteSpeed (OLS). The service owner runs and backs up the backend. Rustiron manages the site account, routing, and TLS configuration. [W577](../validation/S10-W577/README.md) exercised the HTTP lifecycle on a lab host.

## Prepare the routes

1. Confirm that the hostname is free and that each backend listens on IPv4 loopback, `127.0.0.1`.
2. List the HTTP routes. Include `/` and up to seven additional prefixes, each ending in `/`.
3. List up to eight WebSocket prefixes separately. Use the same prefix rules and include `/` if required.
4. Check each port against the enrolled listeners. Use 1024–65535 and exclude 3306 and the enrolled SSH and OLS ports.

OLS uses the longest matching HTTP route and forwards the original `Host`, path, and query. A request to a route prefix without its final slash can receive a redirect. OLS passes through client-supplied `X-Forwarded-For`, which the backend must treat as untrusted. See [the proxy site contract](../technical/PROXY-SITE.md#plan).

## Provision and activate

1. Prepare a schema 1 `proxy_site_provision` plan with the exact site ID, hostname, HTTP routes, and WebSocket prefixes. Each entry contains only `prefix` and `port`.
2. Run `rustiron-plan inspect PLAN.json`. Compare the route and WebSocket rows with the intended backend wiring before signing.
3. Submit the signed request through the coordinator. Wait for `succeeded`. Provision creates the site account and the site files, including the identity file and ACME webroot.
4. Read the active generation and digest using [page 25, step 2](25-DELETE-LIVE-SITE.md#step-2-take-the-site-offline).
5. Sign and submit a separate `config_activate` plan. Use that generation and digest as the predecessor and include the new site and every site that should stay online.
6. Request `/rustiron-site.txt` for the new hostname through OLS and check the site marker. Check the markers of the other served sites.
7. Exercise every HTTP route with an application request that distinguishes its backend. For each WebSocket path, exchange a frame after the upgrade.

Use [the certificate guide](../technical/CERTIFICATES.md) for a separately authorized certificate workflow. W577 checked the ACME webroot and the HTTP listener. Proxy certificate issuance still needs its own lab proof.

For a lab rehearsal, see [the W577 request runner](../validation/S10-W577/lab/pc-request.sh) and [coordinator submission](../validation/S10-W577/lab/09-submit.sh). Use the enrolled authority for the target host.

## Diagnose a backend

Run `/usr/libexec/rustiron/rustiron-control --merge-observation FILE --diagnose --human` with a fresh executor observation. Read each `proxy` finding for the site. See [health diagnoses](../technical/HEALTH-DIAGNOSES.md).

| Finding | Action |
| --- | --- |
| `ok` | The port has a loopback listener. Use an application request to check its response. |
| `warn`, no listener | Check the external service and its configured port. Requests to the stopped backend can return HTTP 503. |
| `warn`, listener beyond loopback | Inspect the service's bind addresses and restore its loopback-only binding. |
| Listener information unavailable | Check observation freshness and the coordinator's access to the listener tables. |

Activation checks the identity file. A backend can be down even when activation succeeds.

## Take the site offline and delete it

1. Follow [page 25, step 2](25-DELETE-LIVE-SITE.md#step-2-take-the-site-offline). Submit a signed activation that omits this site and retains every other served site.
2. Check that the removed hostname's identity file returns 404 and that the other site markers still answer.
3. Prepare a schema 2 `site_delete` plan naming the site ID and hostname. Check `capture operation: none` in `rustiron-plan inspect PLAN.json`.
4. Sign and submit the deletion. Check for `succeeded` and a `deleted` provision. The site ID and hostname stay reserved.
5. Check that the backend is still listening if another site uses it. Manage its lifecycle and DNS through their own procedures.

For an open deletion, use [deletion reconciliation](25-DELETE-LIVE-SITE.md#settle-an-open-deletion). If removal fails, correct the recorded cause before signing another schema 2 request. Deletion is permanent.
