// the named concern — the exhaustive wallet-state matrix dimensions and the two invariants it proves over
// the REAL the named concern projection and the named concern selectors/boot-audit. Frozen data; matrix.test.ts
// drives every cell. CONTRACT_FREEZE.

export const OPERATION_ROLE_DIMENSION = [
  "RECEIVE_WINDOW",
  "MOVE_DESTINATION",
  "SEND_SOURCE",
  "MOVE_SOURCE",
] as const;

export const LEASE_LIFECYCLE_DIMENSION = ["ACTIVE", "RELEASED"] as const;

export const FLAG_DIMENSION = [false, true] as const;

export const STORED_STATE_DIMENSION = ["AVAILABLE", "PINNED", "QUARANTINED", "RETIRED"] as const;

export const MATRIX_INVARIANTS = {
  noLeasedWalletSelected:
    "A wallet with an active operation lease is never receive-selectable, under any quarantine / retirement / recovery combination.",
  noLeasedWalletSilentlyReleased:
    "A wallet with an active operation lease is never AVAILABLE (PINNED, or QUARANTINED when operator-quarantined); boot audit repairs AVAILABLE->PINNED only, never releases a lease and never clears quarantine.",
} as const;

export const walletStateMatrixContract = {
  dimensions: {
    operationRole: OPERATION_ROLE_DIMENSION,
    leaseLifecycle: LEASE_LIFECYCLE_DIMENSION,
    flag: FLAG_DIMENSION,
    storedState: STORED_STATE_DIMENSION,
  },
  invariants: MATRIX_INVARIANTS,
} as const;
