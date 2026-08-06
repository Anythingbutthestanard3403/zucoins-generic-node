// the crypto-goldens concern.2 — Concern manifest: the unified API schema, state, and event vocabulary freeze.
// Aggregates the complete machine-readable API/schema/event vocabulary into one self-registered
// ConcernManifest for the concern-manifest registry assembly.

import { defineConcernManifest } from "../testkit/concernManifest.ts";
import { API_SCHEMA_VERSION } from "./version.ts";
import { HTTP_ERROR_STATUSES, ERROR_ENVELOPE_FIELDS, CITED_ERROR_CODES } from "./error-vocabulary.ts";
import { IMPLEMENTER_SCOPES, AUTH_CLASSES, REPORTING_HEADERS, BEARER_KEY_EXCLUSIONS } from "./auth-scopes.ts";
import { PG_ENUM_NAMES, PG_ENUMS } from "./pg-enums.ts";
import { DISCOVERY_PATH, DISCOVERY_RESPONSE_FIELDS, DISCOVERY_EXCLUSIONS } from "./discovery.ts";
import { PUBLIC_OPERATION_SCHEMA_SURFACE } from "./operation-schema-surface.ts";

export const API_SCHEMA_CONCERN_MANIFEST = defineConcernManifest({
  concernId: "crypto-goldens",
  decisionRefs: [
    "three-generic-operations",
    "launch-deferral",
    "zkz-amount-grammar",
    "no-network-egress",
    "pull-cursor-authority",
  ],
  frozenValues: {
    apiSchema: {
      concern: "api-schema",
      ticket: "crypto-goldens.2",
      version: API_SCHEMA_VERSION,
      governing: {
        spec: "api-contract; data-model enum vocabulary; state-event reference",
        decisions: ["three-generic-operations", "launch-deferral", "pull-cursor-authority"],
      },
      errorVocabulary: {
        httpStatusCount: HTTP_ERROR_STATUSES.length,
        envelopeFields: ERROR_ENVELOPE_FIELDS,
        citedErrorCodes: CITED_ERROR_CODES,
      },
      authScopes: {
        implementerScopes: IMPLEMENTER_SCOPES,
        authClasses: AUTH_CLASSES,
        reportingHeaders: REPORTING_HEADERS,
        bearerKeyExclusions: BEARER_KEY_EXCLUSIONS,
      },
      pgEnums: {
        count: PG_ENUM_NAMES.length,
        names: PG_ENUM_NAMES,
        values: PG_ENUMS,
      },
      discovery: {
        path: DISCOVERY_PATH,
        responseFields: DISCOVERY_RESPONSE_FIELDS,
        exclusions: DISCOVERY_EXCLUSIONS,
      },
      requestResponseSchemas: {
        ticket: "operation-schemas.1",
        count: PUBLIC_OPERATION_SCHEMA_SURFACE.length,
        definitions: PUBLIC_OPERATION_SCHEMA_SURFACE,
      },
    },
  },
  goldenRefs: [
    {
      path: "src/api-schema/gen/api-schema.json",
      sha256: "f30dd07bdd5e5ae63c41d47a461c94ef5a28546eb55bd047bd4c86ca1c366fc7",
    },
  ],
  scanRules: [
    "forbidden-terms:packages/generic-node-contracts/src",
    "dependency-boundary:packages/generic-node-contracts/src",
  ],
  sourceDocCitations: [
    "api-contract: error vocabulary",
    "api-contract: authentication classes",
    "api-contract: discovery endpoint",
    "api-contract: event pull",
    "api-contract: operation routes",
    "data-model: enum vocabulary",
    "state-event reference: operations and events",
    "decision: three-generic-operations",
    "decision: launch-deferral",
    "decision: zkz-amount-grammar",
    "decision: no-network-egress",
    "decision: pull-cursor-authority",
  ],
});
