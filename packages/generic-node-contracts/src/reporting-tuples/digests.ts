// the reporting node-event purpose — Digest, signature, and event-hash pins for the request and event tuple goldens.
// The request/event A digests and signatures reproduce the canonical golden values
// exactly (cross-validated in the freeze test with node:crypto); event B is the null-field /
// chained fixture the reporting node-event purpose adds for the null-case + hash-chain ship-gate coverage.

// zp-report-request-v1 (A.8) — signed by the reporting key (A.8 seed 0x04).
export const REPORT_REQUEST_GOLDEN_SHA256 =
  "31a0edb52dea2b193bd56add32363b7afba1021c5f9820b8c2ee3ea263cfc463" as const;
export const REPORT_REQUEST_GOLDEN_SIGNATURE =
  "Drt5bF_T8OWPyJuth1w6rB-dS0rNBhoh_msFgW8lZiY25FzXiuzeSbKU4x8mA5Et2aIrjBa8dlRGPV6GNF3yAw==" as const;
export const REPORT_REQUEST_QUERY_GOLDEN_SHA256 =
  "e752d80f744472031ac7a85bfe605b938005fb10a2a10d0bffdc83338aca9d81" as const;
export const REPORT_REQUEST_QUERY_GOLDEN_SIGNATURE =
  "UaWgBv7G9FSz2HDawlutYhFXwJe-VdGGyBWyVNpom7Gihe3jBXMvd8CaxisYsVy_DWqvC8F5NV7O7SWhtUD6CQ==" as const;
export const REPORTING_KEY_PUBKEY = "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw=" as const;

// zp-node-event-v1 golden A (A.8) — signed by the node event key (A.8 seed 0x00).
export const NODE_EVENT_A_SHA256 =
  "9644a48d9f0a988c62321a371ad66f993ae4f428ae3a3ee48d0dc290e0560226" as const;
export const NODE_EVENT_A_SIGNATURE =
  "AQPu22VB5jB8nGjtSmbT_U1AN0yvswxFt2nTxD38xeEWgF_n43g-i23l5nMy0u9tBRWaYStxzjNdyllvwXGxDg==" as const;
export const NODE_EVENT_A_EVENT_HASH =
  "1f0ec14dd26b58d3ce4200a18125080951b0e391c6ec081f71b8c49d44b8f4be" as const;

// zp-node-event-v1 golden B — null wallet_id, chained off A (previous_event_hash == A's event_hash).
export const NODE_EVENT_B_SHA256 =
  "42c27944165f242f2c4fc276ff369da58ed6055ffd71c2788f1f6fe73aec2e2c" as const;
export const NODE_EVENT_B_SIGNATURE =
  "lYyU11UCfQMvAS5KMMZKU9Cg6_Qvo6HbcLNz_ulD0WuBNWherIa3iLZeEiNla-gkx1qNsyDtGYJNHIpqeHSdCg==" as const;
export const NODE_EVENT_B_EVENT_HASH =
  "ff6f8bbadf5e50f8d0476802341eec50b8ffff4268d41591537b04e3d255ecd5" as const;

export const NODE_EVENT_KEY_PUBKEY = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=" as const;
