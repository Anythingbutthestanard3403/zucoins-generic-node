// Unified cryptographic golden-vector fixture set (A.8).
// This module aggregates ALL frozen golden bytes from A.8.1 (SplitChain) and A.8.2 (suite tuples)
// into one authoritative reference. Each golden is independently reproducible from the A.8 test-only
// Ed25519 seeds using only node:crypto — no gateway import, no environment-key read, no submission.
//
// Covers A.1.1 (suite serializer), A.1.2 (SplitChain native signing), A.8 (goldens),
// A.9 (negative vectors); artifacts freeze, compatibility-literal preservation, two-timer
// separation, reporting-key enrolment.
// The byte-exact signing rule: byte-exact JSON.stringify signing — never reformat.

// --- A.8 test-only Ed25519 seed roles ---
export const SEED_ROLES = {
  "0x00": "node identity/event",
  "0x01": "device",
  "0x02": "sender wallet",
  "0x03": "receiver wallet",
  "0x04": "reporting",
  "0x05": "disposable predecessor counterparty wallet",
} as const;

export const SEED_PUBLIC_KEYS = {
  node: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=",
  device: "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
  sender: "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=",
  receiver: "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=",
  reporting: "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw=",
  predecessor: "bnoc3Smwt4_ROvTFWY_v9O8qlxZuPKby5Pv8zYBQW_E=",
} as const;

// --- A.8 fixture identifiers ---
export const FIXTURE_IDS = {
  node_id: "11111111-1111-4111-8111-111111111111",
  implementer_id: "22222222-2222-4222-8222-222222222222",
  operation_id: "33333333-3333-4333-8333-333333333333",
  destination_wallet_id: "44444444-4444-4444-8444-444444444444",
  source_wallet: "55555555-5555-4555-8555-555555555555",
  destination_id: "66666666-6666-4666-8666-666666666666",
  nonce: "99999999-9999-4999-8999-999999999999",
  device_key_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  event_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  event_id_b: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
  reporting_key_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
  transfer_code: "golden-transfer-code-v1",
} as const;

// --- A.8.0 SEND transfer-code golden inner (the receive-golden transfer-code concern freeze) ---
export const SEND_PARTIAL_STEP_1_PREIMAGE =
  '{"type":"unique_combinable","version":"2","unix_time_secs":"1784332800.125","signer_steps":2,"step_1_signer":"sender","step_2_signer":"receiver","step_1_key_public__base64urlsafe":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=","step_2_key_public__base64urlsafe":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","step_1_state":{"amount":"7.75"},"step_2_state":{"amount":"2.25"},"previous_step_1_state_signature":"","previous_step_2_state_signature":"","expiry__unix_time_secs":"1784336400","message":"zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3"}' as const;

// Exact A.8.0 step-2 preimage string (JSON.stringify({inner, step_1_signature})).
// Asserted as a full string — never regenerated via parse→stringify in tests (A.8.0 / ZTR-1174).
export const SEND_PARTIAL_STEP_2_PREIMAGE =
  '{"inner":{"type":"unique_combinable","version":"2","unix_time_secs":"1784332800.125","signer_steps":2,"step_1_signer":"sender","step_2_signer":"receiver","step_1_key_public__base64urlsafe":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=","step_2_key_public__base64urlsafe":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","step_1_state":{"amount":"7.75"},"step_2_state":{"amount":"2.25"},"previous_step_1_state_signature":"","previous_step_2_state_signature":"","expiry__unix_time_secs":"1784336400","message":"zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3"},"step_1_signature":"Rq6Oyn7HEISIb1t3dRuSv-czb33rsWAUmiZe2YmBTK813iHOfNXGF8fIzenv_UENGqUzKJl6f1iTpeAMfnHeAA=="}' as const;

export const SEND_PARTIAL_DIGESTS = {
  step_1_sha256: "f0e12e993cc4d6b452162cd49b2699b9f912d7a2bf3d8ddd418e3a29c6bbf0b7",
  step_1_signature: "Rq6Oyn7HEISIb1t3dRuSv-czb33rsWAUmiZe2YmBTK813iHOfNXGF8fIzenv_UENGqUzKJl6f1iTpeAMfnHeAA==",
  step_2_sha256: "d754e48b2e50bb2c1e67271c42f54f3f3a021d927b8ddc6c3cbff1d7c4327ea5",
  step_2_signature: "glzeHcjv9PxEj-oLH-HDKZb5elh1XSb1e5NpPBw7WFcGD-EcBy10bsRX9V6i4JI9G7qO7JtE-ZHXZH4RPUYpDQ==",
  full_tx_sha256: "942d83e5cd973ae50db0496d2e2836411db902ec855490d570dd423baf410d47",
  transfer_code_sha256: "4b3e384d7c1774a450fdf9f74d338d1c6802a1057b2fd49e23c78244912c18f4",
} as const;

// --- A.8.3 SEND_EXTERNAL redemption golden (ZTR-149 / GN-016.3 / ZTR-1174) ---
// Byte-for-byte A.8.0 inner except expiry__unix_time_secs = "1784333100"
// (= floor(formation) 1784332800 + SEND_REDEMPTION_WINDOW_SECS 300). Tier-3 raw bytes also
// live under goldens/send-redemption/ (no trailing newline); digest pinned below.
export const SEND_REDEMPTION_STEP_1_PREIMAGE =
  '{"type":"unique_combinable","version":"2","unix_time_secs":"1784332800.125","signer_steps":2,"step_1_signer":"sender","step_2_signer":"receiver","step_1_key_public__base64urlsafe":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=","step_2_key_public__base64urlsafe":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","step_1_state":{"amount":"7.75"},"step_2_state":{"amount":"2.25"},"previous_step_1_state_signature":"","previous_step_2_state_signature":"","expiry__unix_time_secs":"1784333100","message":"zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3"}' as const;

export const SEND_REDEMPTION_DIGESTS = {
  step_1_sha256: "46ba7528a9a757bd2bf50e2950256663aae9d20a51b485b71d511ac74b38662d",
  step_1_signature: "KKyZRQpHR7Xt3QhUXe0eki2iJC9sGYJ13tDzMN5lpQXA3ets0_7PPHZgOmbxDq2R9Hd7TPN_8Su-QVkuLcFyBA==",
  /** SHA-256 of the on-disk golden file bytes (must equal step_1_sha256 — file carries the preimage only). */
  preimage_file_sha256: "46ba7528a9a757bd2bf50e2950256663aae9d20a51b485b71d511ac74b38662d",
} as const;

// --- A.8.1 SplitChain RECEIVE golden (predecessor transaction) ---
export const PREDECESSOR_STEP_1_PREIMAGE =
  '{"type":"unique_combinable","version":"2","unix_time_secs":"1784332700","signer_steps":2,"step_1_signer":"sender","step_2_signer":"receiver","step_1_key_public__base64urlsafe":"bnoc3Smwt4_ROvTFWY_v9O8qlxZuPKby5Pv8zYBQW_E=","step_2_key_public__base64urlsafe":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=","step_1_state":{"amount":"0"},"step_2_state":{"amount":"10"},"previous_step_1_state_signature":"BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQ==","previous_step_2_state_signature":""}' as const;

export const PREDECESSOR_DIGESTS = {
  step_1_sha256: "9bda00a6bbb423a2ea3a9ee2660742dded80562ad58acde106097e2be0583bec",
  step_1_signature: "MsWTpjUtoofWFb13BCpLqLB6tgYiasFakfd2hufS2V2dHg7N2PdRe8n-wrqQhJKc3-Bml7xK6jUfEv2BBiPxAA==",
  step_2_sha256: "07c6dd592f1dd3aa4e70c58f6ab2f92beaa4153d988ae240e6266c41afa22ce5",
  step_2_signature: "IfsGs-NrmBAQ6VWohtlXDcyrd830Agx1IzW8rcHiqYqndeGLoG8b297PjqC-grrIXFrl3GgDcV2qi6xJBlerCQ==",
  settled_sha256: "51dd611df7564d3cac3bdf8a3415ce9326ee29b920daa1338447c57a4c78505b",
} as const;

// --- A.8.1 SplitChain RECEIVE golden (target transaction) ---
export const TARGET_STEP_1_PREIMAGE =
  '{"type":"unique_combinable","version":"2","unix_time_secs":"1784332800.125","signer_steps":2,"step_1_signer":"sender","step_2_signer":"receiver","step_1_key_public__base64urlsafe":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=","step_2_key_public__base64urlsafe":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","step_1_state":{"amount":"7.75"},"step_2_state":{"amount":"2.25"},"previous_step_1_state_signature":"IfsGs-NrmBAQ6VWohtlXDcyrd830Agx1IzW8rcHiqYqndeGLoG8b297PjqC-grrIXFrl3GgDcV2qi6xJBlerCQ==","previous_step_2_state_signature":"","expiry__unix_time_secs":"1784336400","message":"zp1:33333333-3333-4333-8333-333333333333:ord_7YQ3"}' as const;

export const TARGET_DIGESTS = {
  step_1_sha256: "ce0741df9ed652b25d0294746c67acd6d9ecb4e3318c3691582fc2acdd52be51",
  step_1_signature: "wpAPEHD-wRRyfdoLM5FUgwS5OhCVwkQBV5w-XFDSx_VK19QiW5szD6Cuy1ogiNlIlvWtx4LlZPIdAm81eKX0BA==",
  step_2_sha256: "163d8ef498c09a58d621ed2673c50ed89e79272fcfd14251661c36940e1bb9d0",
  step_2_signature: "uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw==",
  settled_sha256: "5554ffa03050cb94173406a85a50aa72c4eca604ab630f0511e61bec7969aebf",
  transfer_code_sha256: "4b3e384d7c1774a450fdf9f74d338d1c6802a1057b2fd49e23c78244912c18f4",
} as const;

// --- A.8.2 Suite tuple golden preimages (exact preimage_text per A.1.1) ---
export const SUITE_GOLDEN_PREIMAGES = {
  "zp-receive-expected-v1":
    'zp-receive-expected-v1\n{"purpose":"zp-receive-expected-v1","canonical_version":1,"node_id":"11111111-1111-4111-8111-111111111111","implementer_id":"22222222-2222-4222-8222-222222222222","operation_id":"33333333-3333-4333-8333-333333333333","receiver_wallet_id":"55555555-5555-4555-8555-555555555555","receiver_pubkey":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","amount_zkz":"2.25","discriminator":"33333333-3333-4333-8333-333333333333","anchor":"ord_7YQ3","receiver_t0_fingerprint":"0000000000000000000000000000000000000000000000000000000000000000","expiry_unix_time_secs":"1784336400","after_landing":{"kind":"HOLD","destination_id":null},"transfer_code_sha256":"104eb00c3bda958b82b7ce5a24e582dd9efa3e63d2192838fe26b5b23dcb2bab"}',
  "zp-move-internal-expected-v1":
    'zp-move-internal-expected-v1\n{"purpose":"zp-move-internal-expected-v1","canonical_version":1,"node_id":"11111111-1111-4111-8111-111111111111","implementer_id":"22222222-2222-4222-8222-222222222222","operation_id":"33333333-3333-4333-8333-333333333333","source_wallet_id":"55555555-5555-4555-8555-555555555555","source_pubkey":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=","destination_id":"66666666-6666-4666-8666-666666666666","destination_wallet_id":"44444444-4444-4444-8444-444444444444","destination_pubkey":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","amount_zkz":"2.25","spawned_from_operation_id":null,"references_operation_id":null}',
  "zp-send-external-expected-v1":
    'zp-send-external-expected-v1\n{"purpose":"zp-send-external-expected-v1","canonical_version":1,"node_id":"11111111-1111-4111-8111-111111111111","implementer_id":"22222222-2222-4222-8222-222222222222","operation_id":"33333333-3333-4333-8333-333333333333","source_selector":{"kind":"WALLET_ID","wallet_id":"55555555-5555-4555-8555-555555555555"},"source_pubkey":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=","destination_address":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","amount_zkz":"2.25","references_operation_id":null}',
  "zp-send-external-approval-v1":
    'zp-send-external-approval-v1\n{"purpose":"zp-send-external-approval-v1","canonical_version":1,"node_id":"11111111-1111-4111-8111-111111111111","operation_id":"33333333-3333-4333-8333-333333333333","source_selector":{"kind":"WALLET_ID","wallet_id":"55555555-5555-4555-8555-555555555555"},"source_pubkey":"gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q=","destination_address":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","amount_zkz":"2.25","references_operation_id":null,"nonce":"99999999-9999-4999-8999-999999999999","issued_at":"2026-07-18T00:00:00.000Z","expires_at":"2026-07-18T00:05:00.000Z"}',
  "zp-destination-bless-v1":
    'zp-destination-bless-v1\n{"purpose":"zp-destination-bless-v1","canonical_version":1,"node_id":"11111111-1111-4111-8111-111111111111","destination_id":"66666666-6666-4666-8666-666666666666","wallet_id":"44444444-4444-4444-8444-444444444444","wallet_pubkey":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","nonce":"99999999-9999-4999-8999-999999999999","issued_at":"2026-07-18T00:00:00.000Z","expires_at":"2026-07-18T00:05:00.000Z"}',
  "zp-device-enrol-v1":
    'zp-device-enrol-v1\n{"purpose":"zp-device-enrol-v1","canonical_version":1,"node_id":"11111111-1111-4111-8111-111111111111","new_device_key_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","new_device_public_key":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=","label":"golden-device","nonce":"99999999-9999-4999-8999-999999999999","issued_at":"2026-07-18T00:00:00.000Z","expires_at":"2026-07-18T00:05:00.000Z"}',
  "zp-report-request-v1":
    'zp-report-request-v1\n{"purpose":"zp-report-request-v1","canonical_version":1,"node_id":"11111111-1111-4111-8111-111111111111","implementer_id":"22222222-2222-4222-8222-222222222222","method":"POST","path":"/v1/operations/33333333-3333-4333-8333-333333333333/verification-complete","body_sha256":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","nonce":"99999999-9999-4999-8999-999999999999","issued_at":"2026-07-18T00:00:00.000Z","expires_at":"2026-07-18T00:01:00.000Z"}',
  "zp-node-event-v1-golden-a":
    'zp-node-event-v1\n{"purpose":"zp-node-event-v1","canonical_version":1,"node_id":"11111111-1111-4111-8111-111111111111","event_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","seq":"1","operation_id":"33333333-3333-4333-8333-333333333333","wallet_id":"55555555-5555-4555-8555-555555555555","event_type":"receive.ready","data_sha256":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","previous_event_hash":null,"created_at":"2026-07-18T00:00:00.000Z"}',
  "zp-node-event-v1-golden-b":
    'zp-node-event-v1\n{"purpose":"zp-node-event-v1","canonical_version":1,"node_id":"11111111-1111-4111-8111-111111111111","event_id":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","seq":"2","operation_id":"33333333-3333-4333-8333-333333333333","wallet_id":null,"event_type":"operation.needs_attention","data_sha256":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","previous_event_hash":"1f0ec14dd26b58d3ce4200a18125080951b0e391c6ec081f71b8c49d44b8f4be","created_at":"2026-07-18T00:00:01.000Z"}',
  "zp-wallet-head-fingerprint-v1":
    'zp-wallet-head-fingerprint-v1\n{"purpose":"zp-wallet-head-fingerprint-v1","canonical_version":1,"wallet_public_key":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","state_kind":"HEAD","s_signature":"uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw==","p_signature":"","b_amount":"2.25","inner_sha256":"ce0741df9ed652b25d0294746c67acd6d9ecb4e3318c3691582fc2acdd52be51","step_1_signature":"wpAPEHD-wRRyfdoLM5FUgwS5OhCVwkQBV5w-XFDSx_VK19QiW5szD6Cuy1ogiNlIlvWtx4LlZPIdAm81eKX0BA==","step_2_signature":"uP0HeCG-ZT1svQK-drwexhc1mrxx4QLBdfgFlw8nqRrwwvcJcPazgcPxp8aMdz7iJricO75II0bUzvwlBUUDDw=="}',
  "zp-reporting-register-v1":
    'zp-reporting-register-v1\n{"purpose":"zp-reporting-register-v1","canonical_version":1,"node_id":"11111111-1111-4111-8111-111111111111","implementer_id":"22222222-2222-4222-8222-222222222222","new_reporting_key_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","new_reporting_public_key":"ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw=","supersedes_key_id":null,"nonce":"99999999-9999-4999-8999-999999999999","issued_at":"2026-07-18T00:00:00.000Z","expires_at":"2026-07-18T00:05:00.000Z"}',
} as const;

export type SuiteGoldenKey = keyof typeof SUITE_GOLDEN_PREIMAGES;

// --- A.8.2 machine-generated outputs (SHA-256 + signature per purpose) ---
export const SUITE_GOLDEN_OUTPUTS = {
  "zp-receive-expected-v1": {
    sha256: "f49635f02d8de86c5b4324f13520cc38c094d79ee2c0df5df60547c590ede498",
    signature: "3NKuFfWanImIVOPKDN9RBv2pUSwsZ6tYypaYyEN_c4z4Zl-TCIC9_y4q5GEM8SYaSWMMgJBa15-UpsXh_9dBBQ==",
    signingKey: "node",
  },
  "zp-move-internal-expected-v1": {
    sha256: "ad964723e07ca2aef3356f1e02990e07b90be49b5387a7095091398a10944a14",
    signature: "LBOpWe9v6yQXGYeerr0oIoW6gm3kF-nga7FrHkANO7jEw3XjkKjqqPYeCshORWQnXMU9kkKV_0-eE_FLmNUpDA==",
    signingKey: "node",
  },
  "zp-send-external-expected-v1": {
    sha256: "f094f981f833c908fae1fa661cb6d9f6c3cdf29bab792f2660b866c588f22cb5",
    signature: "TKbgi1fVDCnik1TscotEf0i8eFp3NuQ3JlSsPMJgy6imF-Nct9KniWMkPv5bUAtDNp7fFXG89YLI5qme6MyWDA==",
    signingKey: "node",
  },
  "zp-send-external-approval-v1": {
    sha256: "d7c03561bd9bc87e302c533f03741c34d44058fc0aaf1b59b17a4f28f8022146",
    signature: "HLd6EN7uw2KHCgRAryuyEh6ljmHsjgvCJ6Ke1Gq3fb0PDV1Vsn3QCzuo51o0VnH9LCbDI3c_s6AFK3NO013ZCA==",
    signingKey: "device",
  },
  "zp-destination-bless-v1": {
    sha256: "9f9b0f61d152037f7d470bed2803e39b22b3f9830cf60f608f4b92c1f294fc70",
    signature: "W490dwQEKHVOCP2npX1QABoGNwDALJ9KqijN7D-yu9b4GRsScdJEcqtOoKq1z0f2EP0Rf5MOaKu9I6hplLa8BQ==",
    signingKey: "device",
  },
  "zp-device-enrol-v1": {
    sha256: "64e6a3213325f01253954b27abeb4ace733c6f57d0cbc888e5f3bd438b789dc9",
    signature: "wW3OFAKEAmF93BfX2m8GkovUBIJUVz_2G6pXuTJMy5CR3xqBoaTo7UrPQjBvqErxqa9CgF5NCBo3GztayvawCw==",
    signingKey: "device",
  },
  "zp-report-request-v1": {
    sha256: "31a0edb52dea2b193bd56add32363b7afba1021c5f9820b8c2ee3ea263cfc463",
    signature: "Drt5bF_T8OWPyJuth1w6rB-dS0rNBhoh_msFgW8lZiY25FzXiuzeSbKU4x8mA5Et2aIrjBa8dlRGPV6GNF3yAw==",
    signingKey: "reporting",
  },
  "zp-reporting-register-v1": {
    sha256: "98fba788ad4ba2141dc400f1cd0f58db3a03b34a00b5a04ecdcfe239e9912e7e",
    signature: "mSzq0luyM9AubD8PrVDBeoSwljM8SGXmUTsXVhVaLJiX0bPQgHKzFwBwIDkGTpm-2CdsINIQObzjOvHvCMCuDA==",
    signingKey: "reporting",
  },
  "zp-node-event-v1-golden-a": {
    sha256: "9644a48d9f0a988c62321a371ad66f993ae4f428ae3a3ee48d0dc290e0560226",
    signature: "AQPu22VB5jB8nGjtSmbT_U1AN0yvswxFt2nTxD38xeEWgF_n43g-i23l5nMy0u9tBRWaYStxzjNdyllvwXGxDg==",
    signingKey: "node",
  },
  "zp-node-event-v1-golden-b": {
    sha256: "42c27944165f242f2c4fc276ff369da58ed6055ffd71c2788f1f6fe73aec2e2c",
    signature: "lYyU11UCfQMvAS5KMMZKU9Cg6_Qvo6HbcLNz_ulD0WuBNWherIa3iLZeEiNla-gkx1qNsyDtGYJNHIpqeHSdCg==",
    signingKey: "node",
  },
  "zp-wallet-head-fingerprint-v1": {
    sha256: "d03a98b770684e577667f9bde01276b196b98db31663f23b0900623d6dffca2a",
    signature: null,
    signingKey: null,
  },
} as const;

// --- Event hash chain (A.6: event_hash = SHA256(preimage_bytes || signature_bytes)) ---
export const EVENT_HASH_CHAIN = {
  golden_a_event_hash: "1f0ec14dd26b58d3ce4200a18125080951b0e391c6ec081f71b8c49d44b8f4be",
  golden_b_event_hash: "ff6f8bbadf5e50f8d0476802341eec50b8ffff4268d41591537b04e3d255ecd5",
} as const;

// --- Compatibility literals (A.2, compatibility-literal preservation) ---
export const COMPAT_LITERALS = {
  zp1Prefix: "zp1:",
  zupayName: "zupay",
  zupaymentsName: "zupayments",
  headers: [
    "X-ZP-Reporting-Key-Id",
    "X-ZP-Reporting-Timestamp",
    "X-ZP-Reporting-Expires-At",
    "X-ZP-Reporting-Nonce",
    "X-ZP-Reporting-Signature",
    "X-ZP-TOTP",
  ],
} as const;
