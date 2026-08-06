// The receive-expiry contract's load-bearing live-chain premise, frozen as ASSUMPTION data
// pointing at live-gateway acceptance. The whole non-terminal-expiry design is valid ONLY while
// this holds; it is not provable in this contract and must be confirmed against the live gateway
// in acceptance.
export const LIVE_CHAIN_PREMISE = {
  premise:
    "No ZKZ can land on a node receiver without that wallet's step-2 signature (v2 receive = 2-signer unique_combinable only).",
  status: "load_bearing_assumption",
  validWhile: "the live gateway is confirmed to expose no receiver-passive credit path.",
  acceptanceGate: "live-gateway-acceptance",
} as const;
