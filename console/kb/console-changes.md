---
title: "Make changes from the Console"
description: "Prepare a change in a form, review it, sign it on your own computer, and follow its result."
category: "console"
order: 5
readMinutes: 5
runbooks: ["Runbook 05","Runbook 34","Runbook 38"]
keywords: ["change","plan","wizard","sign","approve","grant","submit","operation","review","new plan"]
consoleLinks: [{"to":"/plans/new","label":"New plan"},{"to":"/operations","label":"Operations"}]
---

## How a change works {#how}

Every change to your server, such as a new website, a backup, or a new DNS record, is a plan. You review the plan, sign it with your own key on your own computer, and then the server applies it. The Console helps with every step except the signing, which stays on your computer.

- First, fill in a form in the Console.
- Then review what the change will do.
- Copy the commands and run them on your computer to create and sign the plan.
- Apply the signed plan, from the command line or from the Console.
- Follow the result on the Operations page.

## Fill in a form {#form}

Most pages have a button that starts a form: Add website on Websites, Add domain on Domains, the DNS record editor, and New plan on Operations.

Each form checks your input as you type and explains any problem next to the field. The commands appear only when every field is valid, so you never copy a half-finished command.

New plan offers these changes: config activation, backup capture, recovery probe, site provision, credential rotation, and modern app deploy.

## Change several entries at once {#bulk}

On Websites and Backups you can tick several websites and choose Back up now or Test a restore; on Apps, Restart. Each plan names one website or app, so the Console shows one command per entry, each writing its own plan file (plan-1.json, plan-2.json, and so on). Review and sign each plan on your computer, then submit them on the Plans page.

- Nothing changes on the server until you sign and submit the plans.
- Actions without a signed plan are not offered, and nothing is ever removed in bulk.

## Review the change {#review}

Before you sign, the review page shows what the change will touch: which sites, whether every site reloads, how long a pause could last, and what happens if it fails, including any automatic rollback.

Read this page carefully. Signing a plan is what approves it.

## Sign on your computer {#sign}

Use Copy on the commands panel and run the commands on the computer that holds your operator key. They create the plan and its signed approval. The browser and the Console server never see or store your signing key.

:::caution[Your key stays with you]
Never copy your operator key to the server. The Console is built to work without it.
:::

## Apply the signed plan {#apply}

You can apply the signed plan from the command line, with the apply command that the form gives you. If your server's owner turned on signed submission in the Console, you can also load the three signed files (plan.json, grant.json, and grant.json.sig) in the "Submit signed plan" panel. The Console checks them and forwards them unchanged to the server, which checks them again.

When signed submission is off, the panel shows "Read-only mode". That is the default.

## Follow the result {#result}

The Operations page lists every change the server recorded, with its outcome. A change still in progress is never shown as done.

If a change stops halfway, it shows as "Needs attention" and a notification appears at the top of the Console. Open it to see what happened and what to do next. "Troubleshooting" covers these cases.
