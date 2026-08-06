/**
 * SOURCE: the observation-verification spec (buried-landing complete-path walk), the protocol
 * foundation, and the complete-path landing-proof rule (the any-depth complete-path landing
 * proof). the landing-proof index/walk test anchors.
 *
 * Frozen byte-exact fixtures for the ancestry index. The signatures and wallet keys are
 * deterministic, format-valid padded base64url material (86+`==` signature, 43+`=` pubkey); the
 * completed transaction bodies are exact `JSON.stringify` output (the byte-exact signing rule — never
 * reformatted), and each `bodySha256` is the real SHA-256 of its `bodyText`. `ancestry-index.test.ts`
 * recomputes every digest and asserts the pinned value, so these are a real byte-exact anchor, not a
 * transcription. The chain wires genesis -> A (depth 2) -> B (depth 1) -> C (fresh head, depth 0); T
 * is one MOVE transaction observed under both the sender and receiver role-views; A_NORMALIZED is A
 * reformatted (same embedded step-2 signature, different bytes) — the collision / normalized-body anchor.
 */

export const WALLET_W = "81ZErkG0GqsJQR8bMCxaqkD1AT3yuNtdCXx0BwIb6bU=" as const;
export const WALLET_S = "Dluq06UmUqcD-Cd7ZNIJdRxnjy4YMrOMSouTR98Ca_M=" as const;
export const WALLET_R = "dcA14epgmH_8zqL5dfB_qneBpMZd_7jbPLyeNTS3dkE=" as const;

export const LANDING_PROOF_FIXTURES = {
  // Wallet W, hop A: the buried transaction (depth 1 under B). Predecessor is genesis (p = "").
  A: {
    wallet_public_key: WALLET_W,
    wallet_role: "receiver",
    s_signature: "q0rqDmQXm20sFXipEJ861OUR3KCmPu5c7ldDF2W8EcgQ4h9daRmx2CKTD2gl7ocSD6ys22LeZDGWBTFcGIpOnw==",
    p_signature: "",
    step_1_signature: "6GY4udHpOwyXG_1WfjNcgeoJFF71xDNAePM3HcWn-Kcj0s1gxWbk1fbcNmAaj0CfnCQ6MCaTzBgKp39-v2Py1g==",
    step_2_signature: "f4aqh6Z1XQKGWuQXDv8iOdzwZCbJzeALHbMS-Qu42gjzfFIKw0VQS9N5oYEj2yWeLOq2eVu8d7bKkANH6TqUPw==",
    completed_transaction_text:
      '{"inner":{"seq":"A","t0":"1700000000"},"step_1_signature":"6GY4udHpOwyXG_1WfjNcgeoJFF71xDNAePM3HcWn-Kcj0s1gxWbk1fbcNmAaj0CfnCQ6MCaTzBgKp39-v2Py1g==","step_2_signature":"f4aqh6Z1XQKGWuQXDv8iOdzwZCbJzeALHbMS-Qu42gjzfFIKw0VQS9N5oYEj2yWeLOq2eVu8d7bKkANH6TqUPw=="}',
    completed_transaction_sha256: "e9864702a6b659902dddc1fedfdb1ae3968241200b6d8cab2752bf60f7a15a8e",
  },
  // Wallet W, hop B: depth 1 under C. Its predecessor is A (p_B = s_A).
  B: {
    wallet_public_key: WALLET_W,
    wallet_role: "receiver",
    s_signature: "AYyb-tdAQQGib-uBVTYxSU8FanD_1ROqbBiw0qogognZuVw7jLSPjaiaRtjf_h7HxlM6ZZTf3CQ5gQfVav1U3g==",
    p_signature: "q0rqDmQXm20sFXipEJ861OUR3KCmPu5c7ldDF2W8EcgQ4h9daRmx2CKTD2gl7ocSD6ys22LeZDGWBTFcGIpOnw==",
    step_1_signature: "whbK3Cl_-1atE6LtFibwZ1-CmauA8Kk9IIj3cywjPQfs3aXNTcYLWC-YZVGm6xxTnvfjrSmECqWAhNS_186jBQ==",
    step_2_signature: "nsKrIAcRErBUuOeuC7CCpB6ELQuVfWLWdv7Bwwasc6O0IXi39peS68_uFx_eTg7W0nwsEXXPWxNEv-O4uMhSDg==",
    completed_transaction_text:
      '{"inner":{"seq":"B","t0":"1700000100"},"step_1_signature":"whbK3Cl_-1atE6LtFibwZ1-CmauA8Kk9IIj3cywjPQfs3aXNTcYLWC-YZVGm6xxTnvfjrSmECqWAhNS_186jBQ==","step_2_signature":"nsKrIAcRErBUuOeuC7CCpB6ELQuVfWLWdv7Bwwasc6O0IXi39peS68_uFx_eTg7W0nwsEXXPWxNEv-O4uMhSDg=="}',
    completed_transaction_sha256: "e901c85a2d0344357c5f0aa7887f9ce8252cf8704f1d47201e504bb6bb0d48f3",
  },
  // Wallet W, hop C: the fresh verified head (depth 0). Its predecessor is B (p_C = s_B). Walking
  // from C reaches A at depth 2 — the any-depth (N > 1) buried-landing proof.
  C: {
    wallet_public_key: WALLET_W,
    wallet_role: "receiver",
    s_signature: "S-X3J2yK3mj0sdyFJ7AfV421A_sVV_R3_5ND3BLBlbDn5SqGNfT5OW0t4YWGu9tkIQbRZsiz4VNdobv4E2rxYw==",
    p_signature: "AYyb-tdAQQGib-uBVTYxSU8FanD_1ROqbBiw0qogognZuVw7jLSPjaiaRtjf_h7HxlM6ZZTf3CQ5gQfVav1U3g==",
    step_1_signature: "C0ZvZUbGovb55X265L1IaVIjWVGAQNm52UYk2fGW8zf8_4QG9VzO4i-fyXzD0-zskj7B20--CDjY5l1dfayxPA==",
    step_2_signature: "l0pWRITZMkk2AJWpT9NUQItqYD_kkm7XrN3I2EVxi1UKWe7VrnNK9a4sueyC12oN9_u3xMvSo5V6UWIdydfj0w==",
    completed_transaction_text:
      '{"inner":{"seq":"C","t0":"1700000200"},"step_1_signature":"C0ZvZUbGovb55X265L1IaVIjWVGAQNm52UYk2fGW8zf8_4QG9VzO4i-fyXzD0-zskj7B20--CDjY5l1dfayxPA==","step_2_signature":"l0pWRITZMkk2AJWpT9NUQItqYD_kkm7XrN3I2EVxi1UKWe7VrnNK9a4sueyC12oN9_u3xMvSo5V6UWIdydfj0w=="}',
    completed_transaction_sha256: "d0170374e6ee74ea9a77a1c8420eb75e6c8bf64791097b8ea8985c875e691835",
  },
  // Transaction T: one MOVE observed under BOTH the sender (S) and receiver (R) role-views. Same
  // exact body and step-2 signature; distinct wallet and distinct role-relative state signatures.
  T_SENDER: {
    wallet_public_key: WALLET_S,
    wallet_role: "sender",
    s_signature: "WOqyLhgvP5py3WhNoPuWvUR4-6q-VcdOHUgI6uN0zSNz6DyuNQGuuf7hV1TYqtxIiJvh8lDFEMk47j3Yist5SQ==",
    p_signature: "",
    step_1_signature: "du_4LQ9GQ53gRLWkRIaoGVj_Rt5QCc1vRbZWf7F00MzZ4i5F866jb0UUQOI_T4dglWLZfJvC9dWg-KOuzXLv3Q==",
    step_2_signature: "LNqa9r74HeKJRopF7IUff_0MduGhZfxbhAaizyLEcRXClsykUzxFdXGAF1sCQEyOHMkleuqtawiYkncs_eXinQ==",
    completed_transaction_text:
      '{"inner":{"seq":"T","t0":"1700000200"},"step_1_signature":"du_4LQ9GQ53gRLWkRIaoGVj_Rt5QCc1vRbZWf7F00MzZ4i5F866jb0UUQOI_T4dglWLZfJvC9dWg-KOuzXLv3Q==","step_2_signature":"LNqa9r74HeKJRopF7IUff_0MduGhZfxbhAaizyLEcRXClsykUzxFdXGAF1sCQEyOHMkleuqtawiYkncs_eXinQ=="}',
    completed_transaction_sha256: "ea3aea7b1e461592be89979df97eb165c2592aef13e9340a8c05e7478a294baf",
  },
  T_RECEIVER: {
    wallet_public_key: WALLET_R,
    wallet_role: "receiver",
    s_signature: "lqNMI3D0U3_ky9d9o5G98dlpIuzTfS5OkKS9qDOVqYRaz8SmnZ5qrv_kRpkL00AmY-oaV06rP6iNGa9rPw6wjA==",
    p_signature: "",
    step_1_signature: "du_4LQ9GQ53gRLWkRIaoGVj_Rt5QCc1vRbZWf7F00MzZ4i5F866jb0UUQOI_T4dglWLZfJvC9dWg-KOuzXLv3Q==",
    step_2_signature: "LNqa9r74HeKJRopF7IUff_0MduGhZfxbhAaizyLEcRXClsykUzxFdXGAF1sCQEyOHMkleuqtawiYkncs_eXinQ==",
    completed_transaction_text:
      '{"inner":{"seq":"T","t0":"1700000200"},"step_1_signature":"du_4LQ9GQ53gRLWkRIaoGVj_Rt5QCc1vRbZWf7F00MzZ4i5F866jb0UUQOI_T4dglWLZfJvC9dWg-KOuzXLv3Q==","step_2_signature":"LNqa9r74HeKJRopF7IUff_0MduGhZfxbhAaizyLEcRXClsykUzxFdXGAF1sCQEyOHMkleuqtawiYkncs_eXinQ=="}',
    completed_transaction_sha256: "ea3aea7b1e461592be89979df97eb165c2592aef13e9340a8c05e7478a294baf",
  },
  // A reformatted (pretty-printed) A. Same logical content and embedded step-2 signature; different
  // bytes and a different digest. Its `completed_transaction_sha256` here is deliberately A's ORIGINAL
  // digest, so a self-consistency check (recompute vs stored) fails — the normalized-body anchor.
  A_NORMALIZED: {
    completed_transaction_text:
      '{\n  "inner": {\n    "seq": "A",\n    "t0": "1700000000"\n  },\n  "step_1_signature": "6GY4udHpOwyXG_1WfjNcgeoJFF71xDNAePM3HcWn-Kcj0s1gxWbk1fbcNmAaj0CfnCQ6MCaTzBgKp39-v2Py1g==",\n  "step_2_signature": "f4aqh6Z1XQKGWuQXDv8iOdzwZCbJzeALHbMS-Qu42gjzfFIKw0VQS9N5oYEj2yWeLOq2eVu8d7bKkANH6TqUPw=="\n}',
    stored_sha256_of_original_A: "e9864702a6b659902dddc1fedfdb1ae3968241200b6d8cab2752bf60f7a15a8e",
    actual_sha256: "970ee3f70f93c9874ba0fbcbb7704b11311d62212032b4b2185bd7a67877fa62",
  },
} as const;
