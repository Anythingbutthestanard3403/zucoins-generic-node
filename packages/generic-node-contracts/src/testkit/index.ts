// `@zucoins/generic-node-contracts/testkit` subpath barrel.
//
// Confinement surface for the guard-free reporting-request signing serializer. This subpath
// exists so `serializeReportRequestPayload` — the money-path (`zp-report-request-v1`) A.1.1
// preimage serializer that DELIBERATELY omits the A.5 60s window guard — is reachable by the
// adversarial reporting test fixtures that must construct out-of-window SIGNED requests the
// honest minter refuses to mint, WITHOUT sitting on the package's public API. It is off the
// root `.` barrel (src/index.ts) and off the reporting-tuples concern barrel
// (reporting-tuples/index.ts); the honest, window-enforcing path
// (`buildReportRequestPreimage`) remains the only serializer on the public surface.
//
// The serializer itself is byte-frozen under the byte-exact signing rule: this barrel only re-exports the
// symbol from its defining module — it does not (and must not) alter the emitted bytes. The
// re-export is value-preserving; the frozen A.1.1 preimage is unchanged. See and the
// census guard at src/scan/reporting-serializer-confinement.census.test.ts.

export { serializeReportRequestPayload } from "../reporting-tuples/request-tuple.ts";
