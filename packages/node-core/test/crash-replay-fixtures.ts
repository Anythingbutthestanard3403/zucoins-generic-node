/**
 * Residual crash/replay proof harness — fixtures.
 *
 * Deterministic, offline-only fixture factories. Ed25519 keys are throwaway test keys
 * derived from a fixed seed byte via the testkit's independentCrypto (imported, never
 * wrapped) — no custody surface, never live ZKZ. Preimages are byte-exact JSON.stringify
 * of an ordered object (the byte-exact signing rule). All ids are canonical lowercase uuids (the
 * model's named uuid `===` divergence never arises).
 */
import {
  digestPreimage,
  keypairFromSeedByte,
  signPreimage,
  type RawKeypair,
} from "../../generic-node-contracts/src/testkit/independentCrypto.ts";
import {
  addSecs,
  SEND_REDEMPTION_WINDOW_SECS,
  timestampFromSecs,
  type MutableRow,
  type UnixSecsString,
} from "./crash-replay-model.ts";

export const OPERATION_ID = "0ae00000-0000-4000-8000-0000000000a1";
export const OPERATION_ID_FRESH = "0ae00000-0000-4000-8000-0000000000b2";
export const APPROVAL_ID = "0af00000-0000-4000-8000-0000000000a1";
export const APPROVAL_ID_FRESH = "0af00000-0000-4000-8000-0000000000b2";
export const WALLET_ID = "0a100000-0000-4000-8000-0000000000a1";
export const LEASE_GROUP_ID = "0a1e0000-0000-4000-8000-0000000000a1";
export const SOURCE_OBSERVATION_ID = "0b5e0000-0000-4000-8000-0000000000a1";
export const DESTINATION_OBSERVATION_ID = "0b5e0000-0000-4000-8000-0000000000d1";
export const FRESH_SOURCE_OBSERVATION_ID = "0b5e0000-0000-4000-8000-0000000000f1";
export const FRESH_DESTINATION_OBSERVATION_ID = "0b5e0000-0000-4000-8000-0000000000f2";

/** The injected formation clock (integer-seconds string). T0_form = floor(node_clock) at
 *  sign-intent FORMATION — never the approval's issued_at, never wall clock at assertion
 *  time (anchored to formation). */
export const FORMATION_CLOCK_SECS: UnixSecsString = "1800000000";
/** The approval was issued 120s BEFORE formation; a T1-anchored fixture must differ. */
export const APPROVAL_ISSUED_AT_SECS: UnixSecsString = addSecs(FORMATION_CLOCK_SECS, -120);

export const T2_SECS: UnixSecsString = addSecs(FORMATION_CLOCK_SECS, SEND_REDEMPTION_WINDOW_SECS);

export const CHAIN_LINK = `${"c".repeat(86)}==`;
export const DESTINATION_ADDRESS = `${"D".repeat(43)}=`;
export const AMOUNT_ZKZ = "25";

export const KEY_SEED_BYTE = 0x5e;
export const ROTATED_KEY_SEED_BYTE = 0x71;

export const fixtureKeypair = (seedByte: number = KEY_SEED_BYTE): RawKeypair =>
  keypairFromSeedByte(seedByte);

/** Byte-exact preimage construction (the byte-exact signing rule): JSON.stringify of the ordered fields
 *  object, exactly once, never re-formatted. */
export const makeInnerPreimage = (fields: Readonly<Record<string, string>>): string =>
  JSON.stringify(fields);

/** The canonical scenario preimage fields, in frozen SIGN_INTENT_FROZEN_AFTER_EXISTS
 *  order: the five signed members map 1:1 onto preimage fields. */
export const baselineInnerFields = (
  overrides: Readonly<Record<string, string>> = {},
): Readonly<Record<string, string>> => ({
  chain_link: CHAIN_LINK,
  redemption_time: FORMATION_CLOCK_SECS,
  redemption_expiry: T2_SECS,
  destination_address: DESTINATION_ADDRESS,
  amount_zkz: AMOUNT_ZKZ,
  ...overrides,
});

export const BASELINE_PREIMAGE_TEXT = makeInnerPreimage(baselineInnerFields());
export const BASELINE_PREIMAGE_SHA256 = digestPreimage(BASELINE_PREIMAGE_TEXT);

/** Non-ASCII + astral-plane preimages: makes the UTF-8-vs-UTF-16 encoding decision
 *  observable (JS .length counts UTF-16 code units; the signed bytes are UTF-8). */
export const NON_ASCII_PREIMAGE_TEXT = makeInnerPreimage(
  baselineInnerFields({ destination_address: "Café-rencontre-é" }),
);
export const ASTRAL_PREIMAGE_TEXT = makeInnerPreimage(
  baselineInnerFields({ destination_address: "𝕏🚀-astral" }),
);

export interface RebuiltVariant {
  readonly label: string;
  readonly text: string;
}

/** Genuinely-rebuilt-from-parse byte variants of BASELINE_PREIMAGE_TEXT: the same logical
 *  payload, different bytes. A canonicalizing oracle would silently accept these; the
 *  persisted-digest comparator MUST reject every one (the byte-exact signing rule negative control). */
export const REBUILT_PREIMAGE_VARIANTS: readonly RebuiltVariant[] = (() => {
  const parsed = JSON.parse(BASELINE_PREIMAGE_TEXT) as Record<string, string>;
  const reordered: Record<string, string> = {};
  for (const key of Object.keys(parsed).reverse()) {
    reordered[key] = parsed[key];
  }
  const variants: RebuiltVariant[] = [
    { label: "pretty-printed", text: JSON.stringify(parsed, null, 2) },
    { label: "key-reordered", text: JSON.stringify(reordered) },
    {
      label: "number-coerced",
      text: BASELINE_PREIMAGE_TEXT.replace(`"amount_zkz":"${AMOUNT_ZKZ}"`, '"amount_zkz":25'),
    },
    { label: "trailing-newline", text: `${BASELINE_PREIMAGE_TEXT}\n` },
    {
      label: "unicode-escape",
      text: makeInnerPreimage(baselineInnerFields({ destination_address: "Café" })).replace(
        "Café",
        "Caf\\u00e9",
      ),
    },
  ];
  for (const variant of variants) {
    if (variant.text === BASELINE_PREIMAGE_TEXT) {
      throw new Error(`rebuilt variant ${variant.label} is byte-identical — control is vacuous`);
    }
  }
  return variants;
})();

/** Construction inputs for one formation pass (the plan is a fixture; the durable rows it
 *  produces go through the parsed constraint model). */
export interface FormationPlan {
  readonly operationId: string;
  readonly approvalId: string;
  readonly walletId: string;
  readonly leaseGroupId: string;
  readonly leaseEpoch: number;
  readonly sourceObservationId: string;
  readonly destinationObservationId: string;
  readonly preimageText: string;
  readonly formationClockSecs: UnixSecsString;
}

export const baselinePlan = (overrides: Partial<FormationPlan> = {}): FormationPlan => ({
  operationId: OPERATION_ID,
  approvalId: APPROVAL_ID,
  walletId: WALLET_ID,
  leaseGroupId: LEASE_GROUP_ID,
  leaseEpoch: 7,
  sourceObservationId: SOURCE_OBSERVATION_ID,
  destinationObservationId: DESTINATION_OBSERVATION_ID,
  preimageText: BASELINE_PREIMAGE_TEXT,
  formationClockSecs: FORMATION_CLOCK_SECS,
  ...overrides,
});

/** A fresh-observation variant for recovery first-formation (operation-flow: recovery re-reads
 *  fresh source/destination observations before persisting the FIRST sign intent). */
export const freshObservationPlan = (overrides: Partial<FormationPlan> = {}): FormationPlan =>
  baselinePlan({
    sourceObservationId: FRESH_SOURCE_OBSERVATION_ID,
    destinationObservationId: FRESH_DESTINATION_OBSERVATION_ID,
    ...overrides,
  });

/** Reads the signed inner expiry (T2) OUT of the exact preimage bytes — the
 *  redemption_expiry_at column is a projection of this value, so it is
 *  derived from the preimage, never hardcoded alongside it. */
const expiryFromPreimageText = (preimageText: string): UnixSecsString => {
  const parsed: unknown = JSON.parse(preimageText);
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("crash-replay fixtures: preimage is not a JSON object");
  }
  const expiry = (parsed as Record<string, unknown>)["redemption_expiry"];
  if (typeof expiry !== "string") {
    throw new Error("crash-replay fixtures: preimage carries no string redemption_expiry");
  }
  return expiry;
};

export const makeSignIntentRow = (plan: FormationPlan): MutableRow => ({
  operation_id: plan.operationId,
  approval_id: plan.approvalId,
  source_wallet_id: plan.walletId,
  source_t0_observation_id: plan.sourceObservationId,
  destination_t0_observation_id: plan.destinationObservationId,
  lease_group_id: plan.leaseGroupId,
  lease_epoch: plan.leaseEpoch,
  inner_preimage_text: plan.preimageText,
  inner_sha256: digestPreimage(plan.preimageText),
  redemption_expiry_at: timestampFromSecs(expiryFromPreimageText(plan.preimageText)),
  prepared_at: timestampFromSecs(plan.formationClockSecs),
});

export const makeAttemptRow = (plan: FormationPlan): MutableRow => ({
  operation_id: plan.operationId,
  attempt_no: 1,
  attempt_phase: "INNER_PREIMAGE_PERSISTED",
  inner_preimage_text: plan.preimageText,
  inner_sha256: digestPreimage(plan.preimageText),
  step_1_signature: null,
  step_2_preimage_text: null,
  step_2_preimage_sha256: null,
  step_2_signature: null,
  completed_transaction_text: null,
  completed_transaction_sha256: null,
  formed_at: timestampFromSecs(plan.formationClockSecs),
  settled_at: null,
});

/** Constructs the transfer code from the persisted inner text and the persisted step-1
 * signature WITHOUT parsing/reserializing either (operation-flow step 2): the exact inner bytes
 *  are embedded verbatim by template literal. */
export const makeTransferCodeText = (innerText: string, signature: string): string =>
  `{"payload":${innerText},"step_1_signature":"${signature}"}`;

export const makePartialRow = (
  plan: FormationPlan,
  signature: string,
  transferCodeText: string,
): MutableRow => ({
  operation_id: plan.operationId,
  approval_id: plan.approvalId,
  inner_sha256: digestPreimage(plan.preimageText),
  step_1_signature: signature,
  transfer_code_text: transferCodeText,
  transfer_code_sha256: digestPreimage(transferCodeText),
  persisted_at: timestampFromSecs(plan.formationClockSecs),
  first_delivered_at: null,
  last_redelivered_at: null,
  redelivery_count: 0,
});

export const signFixture = (preimageText: string, seedByte: number = KEY_SEED_BYTE): string =>
  signPreimage(preimageText, fixtureKeypair(seedByte).privateKey);
