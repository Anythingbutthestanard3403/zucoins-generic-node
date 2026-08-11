/** Design-time / offline fixtures when live admin APIs are unavailable. */
export const DEMO = {
  equity: "1248.4200",
  equityDelta: "12.40",
  weekVolume: "84.12",
  walletCount: 144,
  poolAvailable: 142,
  poolCap: 200,
  todayVolume: "18.65",
  halt: "clear" as const,
  inFlightWallets: 2,
  lastPollSec: 12,
  /** Closed three-ops surface. */
  threeOps: {
    receive_external: { open: 2, landed_today: 5 },
    move_internal: { open: 1, landed_today: 3 },
    send_external: { open: 1, landed_today: 2 },
  },
  holdWallets: [
    { id: "T1", role: "primary", pubkey: "zkz1q8f2a7c9d0e1f2a3b4c5d6e7f8a9b0c1d27f2a", balance: "982.1000", busy: false },
    { id: "T2", role: "secondary", pubkey: "zkz1qc901aabbccddeeff001122334455667788c901", balance: "266.3200", busy: true },
  ],
  attention: [
    { id: "mv_8f2a91", type: "move" as const, title: "Parked move", detail: "mv_8f2a · 4.2000 ZKZ · 3 attempts", action: "Retry" },
    { id: "xfr_91c00e", type: "transfer" as const, title: "Outgoing awaiting release", detail: "xfr_91c0 · 0.5000 ZKZ", action: "Release" },
    { id: "rcv_3b11c8", type: "receive" as const, title: "Receive needs attention", detail: "rcv_3b11 · observation budget", action: "Inspect" },
  ],
  activity: [
    { type: "move", ref: "mv_8f2a…91", target: "T1 · zkz1q…7f2a", amount: "4.200000", dir: "flat" as const, status: "parked", when: "14:02", action: "Retry" },
    { type: "transfer", ref: "xfr_91c0…0e", target: "zkz1q…aabb", amount: "−0.500000", dir: "out" as const, status: "awaiting_release", when: "13:51", action: "Release" },
    { type: "receive", ref: "rcv_a91f…c2", target: "zkz1qpool…aa", amount: "+2.500000", dir: "in" as const, status: "landed", when: "13:22", action: "View" },
    { type: "receive", ref: "rcv_bb10…9e", target: "zkz1qpool…bb", amount: "0.750000", dir: "flat" as const, status: "open", when: "12:58", action: "View" },
    { type: "transfer", ref: "xfr_20dd…11", target: "zkz1q…99fe", amount: "−1.000000", dir: "out" as const, status: "settled", when: "12:11", action: "View" },
  ],
  wallets: [
    { pubkey: "zkz1qpool001wsampleaaaaaaaaaaaaaaaaaaaaaa", role: "pool", state: "available", balance: "0.0000" },
    { pubkey: "zkz1qpool002wsamplebbbbbbbbbbbbbbbbbbbbbb", role: "pool", state: "allocated", balance: "0.7500" },
    { pubkey: "zkz1q8f2a7c9d0e1f2a3b4c5d6e7f8a9b0c1d27f2a", role: "hold", state: "available", balance: "982.1000" },
  ],
  transfers: [
    { id: "xfr_91c00e", from: "T1", to: "zkz1q…aabb", amount: "0.5000", status: "awaiting_release" },
    { id: "xfr_20dd11", from: "T1", to: "zkz1q…99fe", amount: "1.0000", status: "settled" },
  ],
  /** Design-preview only — never claimed as live BLESSED custody. */
  destinations: [
    {
      destination_id: "dst_demo_pending",
      wallet_id: "wal_demo_1",
      wallet_public_key: "zkz1qdest001samplesaaaaaaaaaaaaaaaaaaaaaaaa",
      state: "PENDING",
      label: "Demo cold sink",
      blessed_at: null,
      retired_at: null,
      move_eligible: false,
      ineligibility_reason: "not_blessed",
    },
    {
      destination_id: "dst_demo_blessed",
      wallet_id: "wal_demo_2",
      wallet_public_key: "zkz1qdest002samplesbbbbbbbbbbbbbbbbbbbbbbbb",
      state: "BLESSED",
      label: "Demo hold sink",
      blessed_at: "2026-07-01T00:00:00.000Z",
      retired_at: null,
      move_eligible: true,
      ineligibility_reason: null,
    },
  ],
  audit: [
    { when: new Date(Date.now() - 600_000).toISOString(), actor: "admin", action: "transfer.create", target: "xfr_91c00e", ip: "10.0.0.2" },
    { when: new Date(Date.now() - 3_600_000).toISOString(), actor: "admin", action: "settings.save", target: "node", ip: "10.0.0.2" },
  ],
  apiKeys: [
    { type: "SITE", prefix: "zp_site_9f2a", created: "2026-06-01", lastUsed: "2h ago" },
    { type: "REPORTING", prefix: "zp_rep_11bc", created: "2026-06-01", lastUsed: "12m ago" },
    { type: "ACTION", prefix: "zp_act_88de", created: "2026-07-10", lastUsed: "never" },
  ],
  settings: {
    reportingPubkey: "zkz1qrep…aa11",
    poolCap: 200,
    holdWalletCount: 2,
    reportingOptIn: true,
    currencyDisplay: "ZKZ",
  },
};

export type DemoBundle = typeof DEMO;
