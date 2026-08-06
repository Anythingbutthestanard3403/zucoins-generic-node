// Digest, signature, and event-hash pins for the implementer-events goldens.
// TEST-ONLY: A.8 seed keys are TEST-ONLY and MUST never be used with live ZKZ.
//
// All values are machine-generated from the A.8 seed-byte-00 node event key and the frozen
// preimage texts. Reproduced byte-for-byte in manifest.freeze.test.ts via node:crypto.

// Node event key (A.8 seed byte 00) — the ONLY signing key for all three tuple types.
export const NODE_EVENT_KEY_PUBKEY = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=" as const;

// zp-implementer-event-v1 golden A — first implementer event, implementer_previous_event_hash null.
export const IMPLEMENTER_EVENT_A_SHA256 =
  "78c8dd8155acec6e4750079e206a6b9733bbcd92c35cc43b64a433d86db803b2" as const;
export const IMPLEMENTER_EVENT_A_SIGNATURE =
  "gl3yJZtJ2xE1imjkIQoxusoQS9K-dE0F1G6VcMwXowxD1YvbmjY43Arv4THnXbJbRpOpF7Ts-7mSnmaE-kIuBw==" as const;
export const IMPLEMENTER_EVENT_A_EVENT_HASH =
  "f55d6203df0445655cc79ac971a864795f2293cf96c316d3931d298a6f460160" as const;

// zp-implementer-event-v1 golden B — null wallet_id, chained off A.
export const IMPLEMENTER_EVENT_B_SHA256 =
  "eee07e39a4bebb8de9880323934d10492cf46980e25e7d084424405eb0691c70" as const;
export const IMPLEMENTER_EVENT_B_SIGNATURE =
  "-FxD01oH-uBpHDHeflAdvyN3YeECqa_eaXXBAR_TU-yUDcPmnLL7_Cm4aktXaHC_wEkrZVZR1IMHEuH7e6EBBQ==" as const;
export const IMPLEMENTER_EVENT_B_EVENT_HASH =
  "5d30760469db67c76d98aa99f68616ef564db7e2c088f6559337d4789af17391" as const;

// zp-implementer-checkpoint-v1 golden — epoch 1, head at implementer_seq 2.
export const IMPLEMENTER_CHECKPOINT_SHA256 =
  "55faede68dee05b764943804b19042c765ea1737df9f3fb98fb9e63887a0e29d" as const;
export const IMPLEMENTER_CHECKPOINT_SIGNATURE =
  "CON3gHuOVhMYDlDTVUSRHlUQyYhuvIBjaT1-qGqgcRp62RcgItwMMlCv1adx4NXwgsZdiZL-XEEw4Yz7wKo9Dg==" as const;

// zp-implementer-keyrotation-v1 golden — rotation at implementer_seq 3.
export const IMPLEMENTER_KEYROTATION_SHA256 =
  "5bf01bd4f011179e5560b38f8ef16b2bbd103ee17e0108d13836e23589fddbdb" as const;
export const IMPLEMENTER_KEYROTATION_SIGNATURE =
  "A_LUzDQTr6eeulmSZIPZc2LT10hVanWoHXqM5CEJUGITkKcMzTdrXIKxh3Enj-wb-4h4nNW8ipAXOjopRzrrBQ==" as const;
