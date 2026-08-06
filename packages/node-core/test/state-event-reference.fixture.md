<!--
Frozen public execution-phase table (phase, applicability, meaning) from the
state/event reference appendix. Committed as a fixture so the execution-phase
vocabulary stays bound to this frozen table rather than minted in code.
-->
## 3. Orthogonal execution phase

Execution phase is a coarse public diagnostic derived from durable transaction, sign-intent, partial,
submit, response, and terminal-evidence subrecords because a public state deliberately does not expose
every crash boundary. It is not a stored `operations` column.

| Phase | Applies to | Meaning |
|---|---|---|
| `NOT_STARTED` | all | No exact next node-signing preimage or external-send sign intent has been persisted. |
| `PREIMAGE_PERSISTED` | receive after inbound validation; move; send | The exact next node-signing preimage is durable and its required node-produced signature is absent. For receive, the exact step-2 preimage is durable and the node receiver step-2 signature is absent; the payer's inbound step-1 signature may already be persisted. For move, the exact inner/node step-1 preimage is durable and the node source step-1 signature is absent. For send, the sign intent is durable and the node step-1 signature and partial are absent. |
| `SIGNED_PERSISTED` | receive; move; send | The node-produced signature corresponding to the persisted next-signing preimage and its associated transaction/partial record are durable; after that node signature is persisted this is the derived public phase. |
| `DELIVERED` | send | The persisted partial was made retrievable. Re-delivery may return only the same bytes. |
| `SUBMIT_STARTED` | receive; move | The durable exact transaction crossed the submit boundary. It is never submitted again. |
| `SUBMIT_RETURNED` | receive; move | A gateway response was captured; the response alone is not settlement. |
| `LANDED_VERIFIED` | all | Terminal observation and lineage proof are durable. |

Phase can only advance, except that a positively proven non-landed move archives the entire attempt and begins a new attempt at `NOT_STARTED`. It never overwrites the old attempt.

## 4. Attention reasons
