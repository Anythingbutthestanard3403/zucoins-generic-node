// Canonical version pin for every `zp-*-v1` purpose.
// Seven purposes get a literal `1`; three purposes whose byte authority lives in sibling
// reporting modules import their canonical version from upstream — never a second source of truth:
//   zp-report-request-v1 → REPORT_REQUEST_CANONICAL_VERSION (reporting-tuples)
//   zp-reporting-register-v1 → REPORTING_REGISTER_CANONICAL_VERSION (reporting-auth)
//   zp-node-event-v1 → NODE_EVENT_CANONICAL_VERSION (reporting-tuples)
// This module is the single lookup for "what canonical_version does purpose X carry?"
// Golden fixtures all carry canonical_version: 1; retained literals are byte-exact.

import {
  RECEIVE_EXPECTED_PURPOSE,
  MOVE_INTERNAL_EXPECTED_PURPOSE,
  SEND_EXTERNAL_EXPECTED_PURPOSE,
  SEND_EXTERNAL_APPROVAL_PURPOSE,
  DESTINATION_BLESS_PURPOSE,
  DEVICE_ENROL_PURPOSE,
  REPORT_REQUEST_PURPOSE,
  NODE_EVENT_PURPOSE,
  WALLET_HEAD_FINGERPRINT_PURPOSE,
  REPORTING_REGISTER_PURPOSE,
  type ZpV1Purpose,
} from "./compat-literals.contract.ts";
import { REPORTING_REGISTER_CANONICAL_VERSION } from "../reporting-auth/register-tuple.ts";
import { REPORT_REQUEST_CANONICAL_VERSION } from "../reporting-tuples/request-tuple.ts";
import { NODE_EVENT_CANONICAL_VERSION } from "../reporting-tuples/event-tuple.ts";

const V1 = 1 as const;

export const CANONICAL_VERSION_FOR_PURPOSE: Readonly<Record<ZpV1Purpose, number>> = {
  [RECEIVE_EXPECTED_PURPOSE]: V1,
  [MOVE_INTERNAL_EXPECTED_PURPOSE]: V1,
  [SEND_EXTERNAL_EXPECTED_PURPOSE]: V1,
  [SEND_EXTERNAL_APPROVAL_PURPOSE]: V1,
  [DESTINATION_BLESS_PURPOSE]: V1,
  [DEVICE_ENROL_PURPOSE]: V1,
  [REPORT_REQUEST_PURPOSE]: REPORT_REQUEST_CANONICAL_VERSION,
  [REPORTING_REGISTER_PURPOSE]: REPORTING_REGISTER_CANONICAL_VERSION,
  [NODE_EVENT_PURPOSE]: NODE_EVENT_CANONICAL_VERSION,
  [WALLET_HEAD_FINGERPRINT_PURPOSE]: V1,
} as const;

export const CANONICAL_VERSION_V1 = V1;
