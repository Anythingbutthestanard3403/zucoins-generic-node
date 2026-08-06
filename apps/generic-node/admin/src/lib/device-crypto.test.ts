import { describe, expect, it } from "vitest";
import {
  buildDestinationBlessPreimage,
  buildDeviceEnrolPreimage,
  DEVICE_CEREMONY_WINDOW_MS,
  isCeremonyLive,
} from "./device-crypto.js";

// Byte-exact A.8 goldens (generic-node-contracts crypto-goldens).
const GOLDEN_ENROL =
  'zp-device-enrol-v1\n{"purpose":"zp-device-enrol-v1","canonical_version":1,"node_id":"11111111-1111-4111-8111-111111111111","new_device_key_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","new_device_public_key":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=","label":"golden-device","nonce":"99999999-9999-4999-8999-999999999999","issued_at":"2026-07-18T00:00:00.000Z","expires_at":"2026-07-18T00:05:00.000Z"}';

const GOLDEN_BLESS =
  'zp-destination-bless-v1\n{"purpose":"zp-destination-bless-v1","canonical_version":1,"node_id":"11111111-1111-4111-8111-111111111111","destination_id":"66666666-6666-4666-8666-666666666666","wallet_id":"44444444-4444-4444-8444-444444444444","wallet_pubkey":"7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=","nonce":"99999999-9999-4999-8999-999999999999","issued_at":"2026-07-18T00:00:00.000Z","expires_at":"2026-07-18T00:05:00.000Z"}';

describe("device-crypto suite preimage builders (byte-exact)", () => {
  it("buildDeviceEnrolPreimage matches A.8 golden", () => {
    expect(
      buildDeviceEnrolPreimage({
        node_id: "11111111-1111-4111-8111-111111111111",
        new_device_key_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        new_device_public_key: "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
        label: "golden-device",
        nonce: "99999999-9999-4999-8999-999999999999",
        issued_at: "2026-07-18T00:00:00.000Z",
        expires_at: "2026-07-18T00:05:00.000Z",
      }),
    ).toBe(GOLDEN_ENROL);
  });

  it("buildDestinationBlessPreimage matches A.8 golden", () => {
    expect(
      buildDestinationBlessPreimage({
        node_id: "11111111-1111-4111-8111-111111111111",
        destination_id: "66666666-6666-4666-8666-666666666666",
        wallet_id: "44444444-4444-4444-8444-444444444444",
        wallet_pubkey: "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E=",
        nonce: "99999999-9999-4999-8999-999999999999",
        issued_at: "2026-07-18T00:00:00.000Z",
        expires_at: "2026-07-18T00:05:00.000Z",
      }),
    ).toBe(GOLDEN_BLESS);
  });

  it("ceremony window is 300s class", () => {
    expect(DEVICE_CEREMONY_WINDOW_MS).toBe(300_000);
    expect(
      isCeremonyLive(
        "2026-07-18T00:00:00.000Z",
        "2026-07-18T00:05:00.000Z",
        Date.parse("2026-07-18T00:02:00.000Z"),
      ),
    ).toBe(true);
    expect(
      isCeremonyLive(
        "2026-07-18T00:00:00.000Z",
        "2026-07-18T00:06:00.000Z",
        Date.parse("2026-07-18T00:02:00.000Z"),
      ),
    ).toBe(false);
  });
});
