# Executive security brief - Mining remote operations and IIoT

**Prepared by:** SAS821S Capstone group T08 (222093471 Kalume, 215103815 Shithindi)
**Data window:** 1-30 April 2019 (access, ticket and telemetry sources aligned to the same window)
**Status of the data:** ToN_IoT research captures plus a documented synthetic access log. This is a
university exercise; none of the accounts, assets or events describe a real organisation.

## What we found

1. **Remote access is the weakest link in this environment.** 213
   privileged actions took place without multi-factor authentication, and
   56 accounts raised at least one behavioural alert during the month.
   15 user-days scored in the *critical* risk band and 42 in the *high* band
   (out of 2,792 user-days in the month).

2. **The strongest single case** involves account `vend069`
   (vendor_technician, vendor), with
   16 privileged actions of which
   16 had no MFA, touching 8
   assets over 4 days. A containment, eradication,
   recovery and monitoring plan is attached to the technical report.

3. **Detection works, but only where the data is complete.** The network intrusion
   classifier reaches an F1 of 0.999 on unseen flows,
   and the Modbus telemetry classifier 0.989. However, when
   half of the collected fields are missing the network detector falls to F1 0.77, so
   telemetry collection reliability is itself a security control.

4. **Unsupervised detection needs a trusted baseline.** Scoring "whatever is rare" gave a
   ROC-AUC of 0.28 - worse than guessing - because in that
   capture attacks are the majority. Learning a known-good baseline first raised it to
   0.72.

5. **Text sources add context the telemetry does not have.**
   225 of 320 maintenance and incident tickets
   matched an ATT&CK for ICS description closely enough to be useful for triage.

## What it would cost us

Under the modelled assumptions, an intrusion that starts with a stolen remote-access
credential reaches the OT zone in **54%** of runs today and a critical OT
asset in **54%**, compromising **30 assets** on average.

## What we recommend, in order

| Priority | Action | Modelled effect |
|---|---|---|
| 1 | Enforce MFA on every remote and privileged session | P(reach OT) falls from 54% to 19% |
| 2 | Restrict IT-OT to OT traffic to an approved flow list | mean assets compromised falls from 30 to 18 |
| 3 | Deploy detection and isolation on jump hosts and engineering workstations | modest on its own, valuable in combination |
| 4 | All three together | P(reach OT) 10%, critical assets 8%, 3 assets |

## What we are not claiming

* The simulation compares control packages under stated assumptions; it does not forecast
  how often a real intrusion would occur.
* The access log is synthetic, so detection results show that the method finds the
  behaviour we injected, not that it has found a real attacker.
* ToN_IoT is a research testbed, not mining equipment; its captures stand in for mining
  IIoT behaviour and the substitution is documented.
