# About This Book

## The Author

Parag Mali is a systems and security engineer who writes about Windows
architecture, cryptographic protocols, and cloud security at paragmali.com.

## Method and Editorial Standard

*The Windows Trust Chain* was written to close a persistent fragmentation in
systems security literature: firmware specifications stop at `ExitBootServices()`,
kernel internals texts stop at `lsass.exe` and access tokens, Active Directory
references stop at `Kerberos` and `AD CS`, and cloud architecture guides treat
the Windows endpoint as an opaque compliance checkbox. Real adversaries chain
across all four tiers seamlessly; defenders need a single, continuous technical
reference that does the same.

Every chapter in this edition adheres to three strict engineering commitments.
First, mechanism precedes policy: every subsystem is traced down to the concrete
data structures, hardware registers, cryptographic constructions, and protocol
messages that enforce its invariant, anchored to primary normative citations
(`[N]`). Second, adversarial analysis is treated with complete candor: every
defense is paired with a structured Attack Catalog and a Theoretical Limits
section isolating the exact boundary between cryptographic validity and
delegated authorization. Third, claims remain verifiable on real machines: every
chapter isolates concise, non-destructive PowerShell, Win32, WMI/CIM, registry,
and cloud CLI queries in its dedicated inspection section so practitioners can
audit running enforcement state rather than policy intent.

## Errata and Feedback

Operating-system builds, microcode floors, and cloud APIs evolve continuously.
While core architectural invariants remain durable, readers who spot an
inaccuracy, broken citation, or build-specific behavior shift are encouraged to
open an issue on GitHub or reach the author via paragmali.com.
