// shared fixtures for the gateway test-adapter suites. Test-support
// only — production src/ must never import testkit.

import type {
  GatewayLimits,
  GatewayObservationRecord,
  GatewaySubmitAttemptRecord,
  ObservationRecorder,
  SubmitAttemptRecorder,
  SubmitAuthorization,
} from "../gateway/index.js";
import type { SettledSplitChainTransaction } from "../protocol/index.js";

export const PRIMARY = "https://gateway-a.invalid/";
export const SECONDARY = "https://gateway-b.invalid/";

export const LIMITS: GatewayLimits = {
  readTimeoutMs: 1_000,
  maxRequestBytes: 4_096,
  maxResponseBytes: 4_096,
};

export const WALLET_KEY = "sender-public-key-alpha";
export const RECEIVER_KEY = "receiver-public-key-beta";

export const AUTHORIZATION: SubmitAuthorization = {
  submitDecisionId: "11111111-1111-4111-8111-111111111111",
  operationId: "22222222-2222-4222-8222-222222222222",
  transactionAttemptNo: 1,
};

// A minimal frozen-shape v2 transaction: unix_time_secs is a SECONDS string by
// design, amounts are strings — never floats.
export function makeTx(
  senderKey: string,
  receiverKey: string,
  previousLink: string,
  step2Signature: string,
): SettledSplitChainTransaction {
  return {
    inner: {
      type: "unique_combinable",
      version: "2",
      unix_time_secs: "1753056000",
      signer_steps: 2,
      step_1_signer: "sender",
      step_2_signer: "receiver",
      step_1_key_public__base64urlsafe: senderKey,
      step_2_key_public__base64urlsafe: receiverKey,
      step_1_state: { amount: "1.00000000000000000000000000000000" },
      step_2_state: { amount: "0.00000000000000000000000000000000" },
      previous_step_1_state_signature: previousLink,
      previous_step_2_state_signature: "genesis",
    },
    step_1_signature: `step-1-sig-${step2Signature}`,
    step_2_signature: step2Signature,
  };
}

export const TX = makeTx(WALLET_KEY, RECEIVER_KEY, "genesis-link", "chain-link-1");

export const READ_ACTION_DATA = { public_key_base64urlsafe: WALLET_KEY };

export function observationRecorder(): ObservationRecorder & {
  records: GatewayObservationRecord[];
} {
  const records: GatewayObservationRecord[] = [];
  return {
    records,
    recordObservation: async (record) => {
      records.push(record);
    },
  };
}

export function submitRecorder(): SubmitAttemptRecorder & {
  records: GatewaySubmitAttemptRecord[];
} {
  const records: GatewaySubmitAttemptRecord[] = [];
  return {
    records,
    recordSubmitAttempt: async (record) => {
      records.push(record);
    },
  };
}
