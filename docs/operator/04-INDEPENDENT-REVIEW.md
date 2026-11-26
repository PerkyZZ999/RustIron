# Prepare critical security review

This procedure prepares the human review before the first production pilot.
Routine development and lab testing do not wait for a human reviewer.
The [autonomy policy](../AUTONOMY.md) defines the critical checkpoint.

## Preconditions

Prepare a frozen candidate after the applicable P01–P09 technical prerequisites pass.
Identify a qualified reviewer who did not write or direct the reviewed implementation.
The reviewer needs Linux/systemd/SELinux, permissions, Rust, hosting, and recovery-boundary expertise for the assigned scope.
The owner approves any fee and external transfer before either action.
The owner can assign another qualified person as reviewer.

## Agent preparation

1. Record the exact commit, supported profile, build identity, and known limitations.
2. Prepare the [reviewer brief](REVIEWER-BRIEF.md) with evidence and unresolved findings.
3. Prepare a secret-free source bundle and verify its contents.
4. Prepare a recovery kit only if the agreed review needs one.
5. Specify scoped read-only recovery access, encrypted transfer, separate passphrase delivery, and revocation.

Git retains the historical bundle and kit procedure at `49e0c7b:docs/operator/04-INDEPENDENT-REVIEW.md`.
Those commands are reference material, not automatic authorization to overwrite tags, read credentials, or send messages.
A text-pattern scan alone does not prove a bundle contains no secrets.

## Review result

The reviewer returns findings with severity, location, reproduction or argument, and a scoped verdict.
Record the exact reviewed commit and exclusions.
Preserve the reviewer's original file under `docs/reviews/independent/`.
Fix Critical/High findings and record retests before production acceptance.
Present residual consequential conditions in one owner checkpoint.

Manual recovery can use an independent agent runner under D-018.
A different human guide follower is optional usability evidence.
Do not ask the security reviewer to become a routine development participant.

## Completion

The critical reviewer assesses the frozen executor, authorization, host isolation, credentials, capture/restore, packaging, and operations.
Expanded browser/public/tenancy boundaries need the affected review scope before exposure.
A lab review, automated test count, or agent verdict does not pass this checkpoint.
The [roadmap](../planning/ROADMAP.md) owns promotion and cutover tasks.
