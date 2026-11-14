# Preface

Every few years, someone dumps `lsass.exe` or replays a cloud token and the
industry is reminded that a Windows enterprise is only as trustworthy as the
most exposed seam in a long architectural chain. Behind an OAuth access token
sits a local broker; behind that broker sits a credential-isolation trustlet;
behind that trustlet sits a hypervisor; behind that hypervisor sits a measured
boot log; and behind that log sits a cryptographic key fused into silicon at
manufacture. Modern Windows is not secured by any single feature. It is secured
by a *chain*: each link verifying the one below it and extending a bounded
guarantee to the link above it, from the CPU's reset vector to a policy decision
evaluated in Microsoft Entra ID.

This book walks that chain in the exact order trust is established:
silicon → kernel → credentials → cloud. For every link, it answers three
engineering questions: *What concrete problem does this mechanism solve, and how
does Windows implement it? Where do real-world adversaries bypass that boundary,
and what theoretical invariants govern those failures? And how do you verify its
active enforcement state on a running system?* That middle question is central.
Every security boundary in Windows has documented limits, and an architect who
understands how a defense works without understanding where its guarantee ends
cannot design compensating controls above it.

## Audience and Scope

This book is written for **systems security architects, principal detection
engineers, incident responders, and platform engineers** who need an exact,
mechanism-level model of what modern Windows protects and why. It is neither an
offensive exploitation manual nor an introductory administration guide. When
offensive tradecraft appears in these pages, from UEFI bootkits and vulnerable
kernel drivers to Kerberos ticket forgery and `Pass-the-PRT`, it appears as
structural gap analysis: isolating the exact assumption that failed so defenders
can engineer durable mitigations. Because few practitioners work simultaneously
across UEFI firmware, kernel memory management, Active Directory cryptography,
and cloud attestation, the book opens with a concise
[Foundations](../chapters/00b-foundations.md) chapter establishing shared
terminology before Part I begins.

## How to Use This Book

Read front to back to see how each architectural guarantee inherits from the
hardware and kernel primitives beneath it, or drop directly into any subsystem
you operate. Every numbered chapter follows the same structural progression
outlined in [How to Read This Book](03-how-to-read.md), allowing you to jump
straight to the architectural deep dive, the six-column attack catalog, the
theoretical limits, or the live diagnostic queries during an incident or design
review.

*Parag Mali, 2026*
