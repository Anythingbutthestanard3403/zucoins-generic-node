// Operator recovery pack v2 (create + open + re-issue).
//
// Format: zp-node-recovery-pack-v2 — Argon2id → AES-256-GCM seal of
// {"v":2,"vault_master_key":"..."}. TOTP is NOT the file key (session+CSRF+TOTP
// gate HTTP only). Ceremony engine remains sole writer of recovery_verified_at.
// Server zeroizes key material after create/prove.
//
// Threat model: the artifact is designed to leave the host, so it must survive
// being in hostile hands. The seal key therefore has to be a high-entropy secret —
// the online prove lockout governs API attempts only and is irrelevant to an
// attacker holding a copy of the file. v1 sealed under a 4–6 digit passcode
// (≤10^6 keyspace, enumerable offline against the same Argon2id); every v1 pack
// ever exported is compromised-if-leaked and must be re-issued and destroyed.
// v1 packs still open, but only through the explicit legacy opt-in below.

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomInt,
  timingSafeEqual,
} from "node:crypto";

import { argon2id } from "@noble/hashes/argon2.js";

/** Frozen outer discriminator (current). */
export const RECOVERY_PACK_FORMAT = "zp-node-recovery-pack-v2" as const;
/** Frozen outer discriminator of the superseded digit-passcode pack. */
export const RECOVERY_PACK_FORMAT_LEGACY_V1 = "zp-node-recovery-pack-v1" as const;
/** Sealed payload version written by createRecoveryPack. */
export const RECOVERY_PACK_PAYLOAD_VERSION = 2 as const;

/** Frozen Argon2id params — unchanged from v1; the KDF was never the weakness. */
export const RECOVERY_PACK_KDF = {
  alg: "argon2id",
  memory_kib: 65_536,
  iterations: 3,
  parallelism: 1,
  hash_len: 32,
} as const;

export const RECOVERY_PACK_AEAD_ALG = "aes-256-gcm" as const;
export const RECOVERY_PACK_SALT_BYTES = 16; // ≥128-bit
export const RECOVERY_PACK_NONCE_BYTES = 12;
export const RECOVERY_PACK_TAG_BYTES = 16;

/**
 * Entropy floor for the pack secret, enforced at creation. 128 bits is the
 * conventional infeasible-search level and matches the rest of the envelope
 * (AES-256-GCM tag, ≥128-bit salt); Argon2id per-guess cost is on top of it.
 * Creation no longer trusts a charset×length proxy (ZTR-1220): the secret must
 * be exactly the generated shape — Crockford base32 × 26 chars (≥130 bits when
 * drawn i.i.d.) — plus structure guards against tiled / monotone draws.
 */
export const RECOVERY_PACK_MIN_ENTROPY_BITS = 128;
/**
 * Degenerate-input guard. Even inside the sanctioned alphabet a short cycle
 * ("ABABAB…") or a narrow character set is not a CSPRNG draw — require spread.
 */
export const RECOVERY_PACK_MIN_DISTINCT_CHARS = 10;
/**
 * Reject long constant-step runs through the alphabet (any step k ≠ 0, not only
 * ±1). A real CSPRNG draw almost never hits a run of this length; hand-rolled
 * "ABCDEF…" / step-2 sequences always do. Threshold calibrated so CSPRNG FPR
 * is ~0 at n=26 / alphabet=32.
 */
export const RECOVERY_PACK_MAX_MONOTONE_RUN = 6;
/**
 * Reject when this many adjacent pairs share one nonzero alphabet delta, even
 * with breaks (broken step-k walks like every-5th-symbol progressions). CSPRNG
 * E[count per delta] ≈ 25/32; ≥10 is effectively zero FPR at n=26.
 */
export const RECOVERY_PACK_MAX_SAME_DELTA_PAIRS = 10;
/**
 * Reject long same-symbol runs ("AAAA…"). Distinct from step-k monotone — a
 * constant symbol is step 0, not ±1.
 */
export const RECOVERY_PACK_MAX_SAME_RUN = 4;
/**
 * Reject ≥ this many distinct doubled-letter blocks (AA…BB…CC…) even when each
 * run is only length 2 — paired-double patterns with digit noise.
 */
export const RECOVERY_PACK_MAX_PAIRED_DOUBLES = 4;
/**
 * Reject a stretch of consecutive A–Z letters (digits break the run). Catches
 * Crockford-mapped dictionary phrases that otherwise look high-spread
 * (CORRECTHORSE…, MASTERKEY…). Threshold 14: CSPRNG redraw rate ~2–3% at n=26.
 */
export const RECOVERY_PACK_MAX_LETTER_RUN = 14;
/**
 * Near-period: a lag-p match run this long (or a match fraction this high) is
 * not an i.i.d. draw — covers "UNITUNITUNIT…" even when period does not divide
 * the secret length.
 */
export const RECOVERY_PACK_MAX_LAG_MATCH_RUN = 6;
export const RECOVERY_PACK_MAX_LAG_MATCH_FRAC = 0.4;
/**
 * Any substring of this length appearing twice is a structure fail (covers
 * near-tiles and short-cycle pads the exact-tiling check misses).
 */
export const RECOVERY_PACK_MAX_REPEATED_SUBSTRING = 4;
/**
 * Reject strict digit↔letter alternation runs (0A1B2C… / A1B2C3…). CSPRNG p99
 * is ~9 at n=26; threshold 10 keeps redraw rate ~0.8%.
 */
export const RECOVERY_PACK_MAX_CLASS_ALTERNATION_RUN = 10;
/**
 * Reject long letter+digit (or digit+letter) pair sequences (A1B2C3… /
 * 0A1B2C…). Distinct from class-alternation: counts complete pairs.
 */
export const RECOVERY_PACK_MAX_CLASS_PAIR_RUN = 6;
/**
 * Keyboard-row / column / diagonal substring length that is not an i.i.d. draw
 * (QWERTY / 12345 / 1QAZ… column walks).
 */
export const RECOVERY_PACK_MAX_KEYBOARD_RUN = 5;
/**
 * Strided constant-delta run length (every s-th symbol, s≥2). Catches
 * BP1CQ2DR3… style broken step-k that continuous monotone misses.
 */
export const RECOVERY_PACK_MAX_STRIDED_MONOTONE_RUN = 6;
/** Bound on secret length accepted on the *open* path (create is fixed-length). */
export const RECOVERY_PACK_SECRET_MAX_CHARS = 1024;

/**
 * Crockford base32 — 32 symbols, no I/L/O/U, so transcription is unambiguous.
 * Creation accepts only this alphabet (exact case); generateRecoverySecret draws
 * from it. Exported so callers / tests pin the same set the node enforces.
 */
export const RECOVERY_PACK_SECRET_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** 26 × log2(32) = 130 bits, drawn one symbol at a time. */
export const RECOVERY_PACK_GENERATED_SECRET_CHARS = 26;

/** Online prove lockout. Governs API attempts only — never offline possession. */
export const RECOVERY_PACK_PROVE_FAIL_THRESHOLD = 5;
export const RECOVERY_PACK_PROVE_LOCKOUT_MS = 15 * 60 * 1000;
export const RECOVERY_PACK_PROVE_WINDOW_MS = 15 * 60 * 1000;

export interface RecoveryPackKdfPublic {
  readonly alg: "argon2id";
  readonly salt_b64url: string;
  readonly memory_kib: 65536;
  readonly iterations: 3;
  readonly parallelism: 1;
  readonly hash_len: 32;
}

export interface RecoveryPackAeadPublic {
  readonly alg: "aes-256-gcm";
  readonly nonce_b64url: string;
}

/** Wire envelope — public fields only; exact names frozen. */
export interface RecoveryPackEnvelope {
  readonly format: typeof RECOVERY_PACK_FORMAT;
  readonly kdf: RecoveryPackKdfPublic;
  readonly aead: RecoveryPackAeadPublic;
  readonly ciphertext_b64url: string;
  /** Hex SHA-256 of ciphertext bytes (decoded). */
  readonly pack_content_sha256: string;
}

export interface RecoveryPackSecretPayload {
  /** 1 only when the caller opted into the legacy path. */
  readonly v: 1 | 2;
  readonly vault_master_key: string;
}

export class RecoveryPackError extends Error {
  readonly code:
    | "invalid_passcode"
    | "invalid_format"
    | "decrypt_failed"
    | "invalid_payload"
    | "master_key_too_short"
    | "weak_secret"
    | "caller_supplied_secret"
    | "legacy_pack_v1";
  constructor(code: RecoveryPackError["code"], message: string) {
    super(message);
    this.name = "RecoveryPackError";
    this.code = code;
  }
}

const DIGITS_ONLY_RE = /^\d+$/;
const SECRET_ALPHABET_RE = new RegExp(
  `^[${RECOVERY_PACK_SECRET_ALPHABET.replace(/[-\\]/g, "\\$&")}]{${RECOVERY_PACK_GENERATED_SECRET_CHARS}}$`,
);

/**
 * Conservative charset estimate: length × log2(observed character-class union).
 * Kept for diagnostics / tests. Creation acceptance is the alphabet×length
 * shape check below — this proxy alone is not an accept path (ZTR-1220).
 */
export function estimateRecoverySecretEntropyBits(secret: string): number {
  if (secret.length === 0) return 0;
  let pool = 0;
  if (/[a-z]/.test(secret)) pool += 26;
  if (/[A-Z]/.test(secret)) pool += 26;
  if (/\d/.test(secret)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(secret)) pool += 33; // ASCII punctuation + space
  return secret.length * Math.log2(pool);
}

/**
 * True when `secret` is an exact tiling of a shorter unit, OR shows near-period
 * structure (long lag-p match run / high match fraction / repeated substring).
 * Exact `n % period === 0` tiling alone missed "UNITUNITUNIT…" pads whose period
 * does not divide 26 (Review B residual class).
 */
function hasRepeatedStructure(secret: string): boolean {
  const n = secret.length;
  // Exact full tilings (period divides n).
  for (let period = 1; period <= Math.floor(n / 2); period++) {
    if (n % period !== 0) continue;
    const unit = secret.slice(0, period);
    if (unit.repeat(n / period) === secret) return true;
  }
  // Near-period: lag-p consecutive matches / match fraction.
  for (let period = 1; period <= Math.floor(n / 2); period++) {
    let match = 0;
    let run = 0;
    let maxRun = 0;
    for (let i = period; i < n; i++) {
      if (secret[i] === secret[i - period]) {
        match += 1;
        run += 1;
        if (run > maxRun) maxRun = run;
      } else {
        run = 0;
      }
    }
    if (maxRun >= RECOVERY_PACK_MAX_LAG_MATCH_RUN) return true;
    if (match / (n - period) >= RECOVERY_PACK_MAX_LAG_MATCH_FRAC) return true;
  }
  // Any substring of length ≥ MAX_REPEATED_SUBSTRING appearing twice.
  const maxLen = Math.min(RECOVERY_PACK_MAX_REPEATED_SUBSTRING + 9, Math.floor(n / 2));
  for (let len = RECOVERY_PACK_MAX_REPEATED_SUBSTRING; len <= maxLen; len++) {
    const seen = new Set<string>();
    for (let i = 0; i <= n - len; i++) {
      const sub = secret.slice(i, i + len);
      if (seen.has(sub)) return true;
      seen.add(sub);
    }
  }
  return false;
}

/**
 * True when ≥ RECOVERY_PACK_MAX_MONOTONE_RUN consecutive symbols step by a
 * constant non-zero alphabet delta (any step k, not only ±1).
 * e.g. "01234567" (k=+1), "02468ACE" (k=+2).
 *
 * Also rejects broken step-k: ≥ MAX_SAME_DELTA_PAIRS adjacent pairs sharing
 * one nonzero delta even with interruptions (5AFMS49E… every-5 walk).
 */
function hasMonotoneAlphabetRun(secret: string): boolean {
  const indexOf = (c: string): number => RECOVERY_PACK_SECRET_ALPHABET.indexOf(c);
  // Track run length for each observed constant delta.
  let run = 1;
  let prevDelta: number | null = null;
  const deltaPairCounts = new Map<number, number>();
  for (let i = 1; i < secret.length; i++) {
    const delta = indexOf(secret[i]!) - indexOf(secret[i - 1]!);
    if (delta !== 0) {
      deltaPairCounts.set(delta, (deltaPairCounts.get(delta) ?? 0) + 1);
    }
    if (delta !== 0 && delta === prevDelta) {
      run += 1;
      if (run >= RECOVERY_PACK_MAX_MONOTONE_RUN) return true;
    } else {
      run = 1;
      prevDelta = delta === 0 ? null : delta;
    }
  }
  for (const count of deltaPairCounts.values()) {
    if (count >= RECOVERY_PACK_MAX_SAME_DELTA_PAIRS) return true;
  }
  // Strided constant-delta (every s-th symbol) — continuous monotone misses
  // digit-broken arithmetic walks like BP1CQ2DR3ES4FT5…
  for (let stride = 2; stride <= 4; stride++) {
    for (let offset = 0; offset < stride; offset++) {
      let strideRun = 1;
      let stridePrev: number | null = null;
      let prevIdx: number | null = null;
      for (let i = offset; i < secret.length; i += stride) {
        const idx = indexOf(secret[i]!);
        if (prevIdx !== null) {
          const delta = idx - prevIdx;
          if (delta !== 0 && delta === stridePrev) {
            strideRun += 1;
            if (strideRun >= RECOVERY_PACK_MAX_STRIDED_MONOTONE_RUN) return true;
          } else {
            strideRun = 1;
            stridePrev = delta === 0 ? null : delta;
          }
        }
        prevIdx = idx;
      }
    }
  }
  return false;
}

/** True when ≥ RECOVERY_PACK_MAX_SAME_RUN identical symbols sit in a row. */
function hasLongSameRun(secret: string): boolean {
  let run = 1;
  for (let i = 1; i < secret.length; i++) {
    if (secret[i] === secret[i - 1]) {
      run += 1;
      if (run >= RECOVERY_PACK_MAX_SAME_RUN) return true;
    } else {
      run = 1;
    }
  }
  // Multiple triple-or-longer same-symbol blocks (AAABBBCCC…) — not i.i.d.
  let blocks = 0;
  run = 1;
  for (let i = 1; i <= secret.length; i++) {
    if (i < secret.length && secret[i] === secret[i - 1]) {
      run += 1;
    } else {
      if (run >= 3) blocks += 1;
      run = 1;
    }
  }
  if (blocks >= 2) return true;
  // Paired doubles with noise (AA1BB2CC3DD4…) — each run is only length 2, so
  // the triple-block and MAX_SAME_RUN guards miss it.
  let doubles = 0;
  for (let i = 0; i < secret.length - 1; ) {
    if (secret[i] === secret[i + 1]) {
      doubles += 1;
      if (doubles >= RECOVERY_PACK_MAX_PAIRED_DOUBLES) return true;
      i += 2;
    } else {
      i += 1;
    }
  }
  return false;
}

/**
 * True when ≥ RECOVERY_PACK_MAX_LETTER_RUN consecutive A–Z letters appear
 * (digits break the run). Crockford-mapped dictionary phrases concentrate
 * letters; CSPRNG draws interleave digits.
 */
function hasLongLetterRun(secret: string): boolean {
  let run = 0;
  for (const c of secret) {
    if (c >= "A" && c <= "Z") {
      run += 1;
      if (run >= RECOVERY_PACK_MAX_LETTER_RUN) return true;
    } else {
      run = 0;
    }
  }
  return false;
}

/**
 * True when ≥ RECOVERY_PACK_MAX_CLASS_ALTERNATION_RUN consecutive symbols
 * alternate digit↔letter class (0A1B2C…, A1B2C3…). Catches patterned
 * skeletons that step-k monotone misses because alphabet deltas are not
 * constant.
 */
function hasClassAlternationRun(secret: string): boolean {
  let run = 1;
  for (let i = 1; i < secret.length; i++) {
    const prevDigit = secret[i - 1]! >= "0" && secret[i - 1]! <= "9";
    const curDigit = secret[i]! >= "0" && secret[i]! <= "9";
    if (prevDigit !== curDigit) {
      run += 1;
      if (run >= RECOVERY_PACK_MAX_CLASS_ALTERNATION_RUN) return true;
    } else {
      run = 1;
    }
  }
  return false;
}

/**
 * True when ≥ RECOVERY_PACK_MAX_CLASS_PAIR_RUN consecutive letter+digit or
 * digit+letter pairs appear (A1B2C3… / 0A1B2C…). Complements class-alternation
 * by counting complete pairs from either alignment.
 */
function hasClassPairRun(secret: string): boolean {
  const isDigit = (c: string): boolean => c >= "0" && c <= "9";
  const isLetter = (c: string): boolean => c >= "A" && c <= "Z";
  for (const offset of [0, 1] as const) {
    for (const kind of ["LD", "DL"] as const) {
      let run = 0;
      let i = offset;
      while (i + 1 < secret.length) {
        const a = secret[i]!;
        const b = secret[i + 1]!;
        const ok =
          (kind === "LD" && isLetter(a) && isDigit(b)) ||
          (kind === "DL" && isDigit(a) && isLetter(b));
        if (ok) {
          run += 1;
          if (run >= RECOVERY_PACK_MAX_CLASS_PAIR_RUN) return true;
          i += 2;
        } else {
          run = 0;
          i += 1;
        }
      }
    }
  }
  return false;
}

/**
 * Physical QWERTY layout (digit row + three letter rows). Used to build
 * column walks (1QAZ / 2WSX / …) and diagonals the row-only list missed.
 * Symbols outside Crockford are dropped when materialising walks.
 */
const KEYBOARD_LAYOUT_ROWS: readonly string[] = [
  "1234567890",
  "QWERTYUIOP",
  "ASDFGHJKL",
  "ZXCVBNM",
];

/**
 * Keyboard rows, columns, diagonals, and multi-column stitches (and reverse)
 * restricted to the Crockford alphabet. A contiguous substring of length
 * ≥ MAX_KEYBOARD_RUN is not an i.i.d. draw.
 */
function buildKeyboardWalks(): readonly string[] {
  const filterCrock = (s: string): string =>
    [...s].filter((c) => RECOVERY_PACK_SECRET_ALPHABET.includes(c)).join("");
  const walks = new Set<string>();
  const add = (raw: string): void => {
    const s = filterCrock(raw);
    if (s.length >= RECOVERY_PACK_MAX_KEYBOARD_RUN) {
      walks.add(s);
      walks.add([...s].reverse().join(""));
    }
  };

  // Horizontal rows + reverse (incl. home-block stitch).
  for (const row of KEYBOARD_LAYOUT_ROWS) add(row);
  add("QWERTYASDFGHZXCVBN");
  add("0123456789");

  // Vertical columns (1QAZ, 2WSX, …) and reverse-each-column (ZAQ1, XSW2, …).
  const maxCol = Math.max(...KEYBOARD_LAYOUT_ROWS.map((r) => r.length));
  const columns: string[] = [];
  for (let c = 0; c < maxCol; c++) {
    let col = "";
    for (const row of KEYBOARD_LAYOUT_ROWS) {
      if (c < row.length) col += row[c]!;
    }
    columns.push(col);
    add(col);
  }

  // Multi-column stitches: operators type whole columns left-to-right
  // (1QAZ2WSX3EDC…) or reverse-column (ZAQ1XSW2…) or reverse column-order.
  const colVariants: readonly (readonly string[])[] = [
    columns,
    columns.map((col) => [...col].reverse().join("")),
  ];
  for (const cols of colVariants) {
    for (let start = 0; start < cols.length; start++) {
      let acc = "";
      for (let end = start; end < cols.length; end++) {
        acc += cols[end]!;
        add(acc);
      }
      // Reverse column-order stitch from this start.
      let racc = "";
      for (let end = start; end >= 0; end--) {
        racc += cols[end]!;
        add(racc);
      }
    }
  }

  // Diagonals down-right and down-left.
  for (let r0 = 0; r0 < KEYBOARD_LAYOUT_ROWS.length; r0++) {
    for (let c0 = 0; c0 < maxCol; c0++) {
      let dr = "";
      let dl = "";
      for (
        let r = r0, c = c0;
        r < KEYBOARD_LAYOUT_ROWS.length && c < KEYBOARD_LAYOUT_ROWS[r]!.length;
        r++, c++
      ) {
        dr += KEYBOARD_LAYOUT_ROWS[r]![c]!;
      }
      for (
        let r = r0, c = c0;
        r < KEYBOARD_LAYOUT_ROWS.length && c >= 0 && c < KEYBOARD_LAYOUT_ROWS[r]!.length;
        r++, c--
      ) {
        dl += KEYBOARD_LAYOUT_ROWS[r]![c]!;
      }
      add(dr);
      add(dl);
    }
  }

  return [...walks];
}

const KEYBOARD_WALKS_CROCKFORD: readonly string[] = buildKeyboardWalks();

function hasKeyboardRowRun(secret: string): boolean {
  const letterSkeleton = [...secret].filter((c) => c >= "A" && c <= "Z").join("");
  for (const walk of KEYBOARD_WALKS_CROCKFORD) {
    if (walk.length < RECOVERY_PACK_MAX_KEYBOARD_RUN) continue;
    for (let len = RECOVERY_PACK_MAX_KEYBOARD_RUN; len <= walk.length; len++) {
      for (let i = 0; i <= walk.length - len; i++) {
        const sub = walk.slice(i, i + len);
        if (secret.includes(sub)) return true;
        // Digit-broken keyboard walks: match on the letter-only skeleton too.
        if (/^[A-Z]+$/.test(sub) && letterSkeleton.includes(sub)) return true;
      }
    }
  }
  return false;
}

/**
 * Common English / media / password-corpus tokens ≥5 letters, Crockford-legal
 * only (no I/L/O/U). Matched against the letter skeleton, leet-folded skeleton,
 * and their reverses so digit-broken and reversed phrases still hit.
 */
const DICTIONARY_TOKENS_MIN5: readonly string[] = [
  "CORRECT",
  "HORSE",
  "BATTERY",
  "STAPLE",
  "PLEASE",
  "LETME",
  "WINTER",
  "COMING",
  "NORTH",
  "FORCE",
  "NEVER",
  "GONNA",
  "MASTER",
  "PASSWORD",
  "HUNTER",
  "QWERTY",
  "MAYTHE",
  "SECRET",
  "BACKUP",
  "ADMIN",
  "LOGIN",
  "WELCOME",
  "MONKEY",
  "DRAGON",
  "SHADOW",
  "PRINCESS",
  "FOOTBALL",
  "BASEBALL",
  "SUPPLY",
  "CHAIN",
  "PHRASE",
  "ORANGE",
  "BANANA",
  "COFFEE",
  "TIGER",
  "EAGLE",
  "RIVER",
  "MOUNTAIN",
  "SUNSET",
  "SUMMER",
  "SPRING",
  "AUTUMN",
  "MONEY",
  "TRUST",
  "VAULT",
  "WALLET",
  "CRYPTO",
  "BITCOIN",
  "RECOVERY",
  "CEREMONY",
  "OPERATOR",
  "APPLE",
  "LETMIN",
  // Media / pangram / song / ticket mnemonics (Review B r3 residual class).
  "QVICK",
  "BROWN",
  "JUMPS",
  "STRANGER",
  "STRANGE",
  "THINGS",
  "PLANET",
  "HACKTHE",
  "JACKDAW",
  "FROZEN",
  "HEISENBERG",
  "BREAKING",
  "YELLOW",
  "MARINE",
  "SVBMARINE",
  "HEAVEN",
  "STAIRWAY",
  "BOHEMIAN",
  "RHAPSODY",
  "FOOBAR",
  "BELIEVE",
  "BELIEVIN",
  "SHALL",
  "ENTROPY",
  "FLOOR",
  "WORKAND",
  "NOPLAY",
  "LOREM",
  "IPSVM",
  "MORPH",
  "ONCEVPON",
  "VPONATIME",
  "YODASHALL",
  "DONTSTOP",
  "HOWNOW",
  "COWFARM",
];

/**
 * Short custody / password tokens (exactly 4). Generic English shorts need
 * ≥2 distinct hits (too common alone in CSPRNG letter skeletons). The custody
 * shortlist below rejects on a single hit — operators paste NODE/PASS/CODE as
 * the whole mnemonic core (Review B r3 MANP1N…NODE…).
 */
const DICTIONARY_TOKENS_LEN4_CUSTODY: readonly string[] = [
  "CODE",
  "PASS",
  "NODE",
  "PACK",
  "ROOT",
  "LOCK",
  "SAFE",
  "OPEN",
  "TEST",
  "DEMO",
  "KEYS",
  "KEYX",
  "PINX",
];
const DICTIONARY_TOKENS_LEN4: readonly string[] = [
  "CODE",
  "PASS",
  "NODE",
  "PACK",
  "THEN",
  "THIS",
  "THAT",
  "HAVE",
  "YOUR",
  "INTO",
  "FROM",
  "LOVE",
  "ROOT",
  "WITH",
  "BACK",
  "LOCK",
  "SAFE",
  "OPEN",
  "TEST",
  "DEMO",
  "USER",
  "HOME",
  "WORK",
  "PLAY",
  "WORD",
  "FISH",
  "BIRD",
  "DARK",
  "BLUE",
  "GOLD",
  "FIRE",
  "WIND",
  "SNOW",
  "RAIN",
  "STAR",
  "MOON",
  "LIFE",
  "TIME",
  "YEAR",
  "WEEK",
  "HAND",
  "HEAD",
  "MIND",
  "SOUL",
  "ONCE",
  "VPON",
  "YODA",
  "DONT",
  "STOP",
  "HACK",
  "JACK",
  "FARM",
  "KEYS",
];

/** Leet fold used only for dictionary skeleton matching (1→I, 0→O, …). */
const LEET_FOLD: Readonly<Record<string, string>> = {
  "0": "O",
  "1": "I",
  "3": "E",
  "4": "A",
  "5": "S",
  "7": "T",
};

function letterSkeleton(secret: string, leet: boolean): string {
  let out = "";
  for (const c of secret) {
    if (c >= "A" && c <= "Z") {
      out += c;
      continue;
    }
    if (leet) {
      const folded = LEET_FOLD[c];
      if (folded !== undefined) out += folded;
    }
  }
  return out;
}

/**
 * True when the letter skeleton (raw or leet-folded, forward or reversed)
 * embeds a ≥5-letter dictionary token, a single custody 4-letter token, or
 * ≥2 distinct generic 4-letter tokens. Catches digit-broken and reversed
 * dictionary phrases the letter-run threshold alone misses.
 */
function hasDictionarySkeleton(secret: string): boolean {
  const bases = [letterSkeleton(secret, false), letterSkeleton(secret, true)];
  const skeletons: string[] = [];
  for (const sk of bases) {
    skeletons.push(sk);
    if (sk.length > 0) skeletons.push([...sk].reverse().join(""));
  }
  for (const sk of skeletons) {
    for (const token of DICTIONARY_TOKENS_MIN5) {
      if (sk.includes(token)) return true;
      // Token reversed inside a forward skeleton (partial reverse phrase).
      if (sk.includes([...token].reverse().join(""))) return true;
    }
    for (const token of DICTIONARY_TOKENS_LEN4_CUSTODY) {
      if (sk.includes(token) || sk.includes([...token].reverse().join(""))) {
        return true;
      }
    }
    let shortHits = 0;
    for (const token of DICTIONARY_TOKENS_LEN4) {
      if (sk.includes(token) || sk.includes([...token].reverse().join(""))) {
        shortHits += 1;
        if (shortHits >= 2) return true;
      }
    }
  }
  return false;
}

/**
 * True when a run of ≥5 consecutive digits is a Fibonacci sequence
 * (each digit = sum of the prior two, exact or mod 10). Catches 112358…
 * offline-searchable prefixes the step-k alphabet walk misses.
 */
function hasFibonacciDigitRun(secret: string): boolean {
  const isFib = (digits: readonly number[]): boolean => {
    if (digits.length < 5) return false;
    let exact = true;
    let mod = true;
    for (let i = 2; i < digits.length; i++) {
      const sum = digits[i - 1]! + digits[i - 2]!;
      if (digits[i] !== sum) exact = false;
      if (digits[i] !== sum % 10) mod = false;
      if (!exact && !mod) return false;
    }
    return exact || mod;
  };
  let run: number[] = [];
  const flush = (): boolean => {
    for (let s = 0; s < run.length; s++) {
      for (let e = s + 5; e <= run.length; e++) {
        if (isFib(run.slice(s, e))) return true;
      }
    }
    run = [];
    return false;
  };
  for (let i = 0; i <= secret.length; i++) {
    const c = secret[i];
    if (c !== undefined && c >= "0" && c <= "9") {
      run.push(Number(c));
    } else if (flush()) {
      return true;
    }
  }
  return false;
}

/**
 * Non-list human-pattern class floor (ZTR-1220 r5 / Review B r4).
 * Finite dictionary / media allowlists alone leave an arms race: the next
 * English/media/geo/song mnemonic still seals. These guards are class-level:
 * digit-constant heads (π/e/√2), ceremony mnemonic pad shape, high Latin-vowel
 * letter skeletons, open English n-gram density, and open-lexicon cover — not a
 * ticket-by-ticket phrase list.
 */
/** Long digit run (head or internal) that is not a CSPRNG shape. */
export const RECOVERY_PACK_MAX_DIGIT_RUN = 8;
/** Latin-vowel fraction (A E I O U Y on leet-folded skeleton) above which a letter-heavy secret is English-like. */
export const RECOVERY_PACK_MAX_LATIN_VOWEL_FRAC = 0.4;
/** Minimum letter-skeleton length paired with the vowel-fraction guard. */
export const RECOVERY_PACK_MIN_LETTERS_FOR_VOWEL_GUARD = 18;
/** Open English bigram hits on a skeleton at/above this density → reject. */
export const RECOVERY_PACK_MAX_ENGLISH_BIGRAM_HITS = 10;
/** Open English trigram hits on a skeleton at/above this density → reject. */
export const RECOVERY_PACK_MAX_ENGLISH_TRIGRAM_HITS = 3;
/** Letters covered by non-overlapping open-lexicon tokens → reject. */
export const RECOVERY_PACK_MIN_ENGLISH_COVER_LETTERS = 8;
/** Cover + elevated vowel fraction (compound nouns without year pad). */
export const RECOVERY_PACK_MIN_ENGLISH_COVER_WITH_VOWEL = 6;
export const RECOVERY_PACK_MIN_VOWEL_FRAC_WITH_COVER = 0.34;
/** Letter count / fraction for year+KEY/ABC ceremony mnemonic pad. */
export const RECOVERY_PACK_MIN_MNEMONIC_PAD_LETTERS = 14;
export const RECOVERY_PACK_MIN_MNEMONIC_PAD_LETTER_FRAC = 0.55;

/** Classic English bigrams (open model; Crockford-safe matching uses letter/leet skeletons). */
const OPEN_ENGLISH_BIGRAMS: ReadonlySet<string> = new Set(
  (
    "TH HE IN ER AN RE ON EN AT ND ED ES NT HA TO OU EA NG AS OR TI IS ET IT AR TE SE HI OF " +
    "DE RO LE SA ME NE CE RA IC NS RI IO WE VE WA TA CA MA BE PE KE YE ST CK WH GH SH CH " +
    "BR CR DR FR GR PR TR WR BL CL FL GL PL SL SM SN SP SW TW SC SK QU"
  ).split(/\s+/),
);

/** Classic English trigrams (open model). */
const OPEN_ENGLISH_TRIGRAMS: ReadonlySet<string> = new Set(
  (
    "THE AND ING HER HAT HIS THA ERE FOR ENT ION HAS NTH TIO ALL VER TER EST THI CON RES " +
    "PRO ARE OUT PER ECT ONE OUR ITH FRO MEN TED ERS ATH EVE OME COM ATE IVE RED"
  ).split(/\s+/),
);

/**
 * Compact open English lexicon (≥4 letters). General vocabulary + household /
 * nature / geo stems — maintained as a class model, not a Review-ticket FA list.
 * Crockford letter-only forms are derived at module load.
 */
const OPEN_ENGLISH_WORDS_RAW: readonly string[] = (
  "THAT WITH HAVE THIS WILL YOUR FROM THEY KNOW WANT BEEN GOOD MUCH SOME TIME VERY WHEN COME HERE JUST LIKE LONG MAKE MANY MORE ONLY OVER SUCH TAKE THAN THEM WELL WERE " +
  "ABOUT AFTER AGAIN BEING EVERY FIRST GREAT HOUSE LARGE NEVER OTHER PLACE POINT RIGHT SMALL SOUND STILL THEIR THESE THING THINK THREE UNDER WATER WHERE WHICH WORLD WOULD WRITE " +
  "PEOPLE SCHOOL MOTHER FATHER FAMILY FRIEND SECOND NUMBER ALWAYS AROUND BECAUSE BEFORE CHANGE DURING FOLLOW HAPPEN LETTER NATURE PICTURE SHOULD ANIMAL BROTHER SISTER " +
  "APPLE ORANGE BANANA TABLE CHAIR HOUSE WATER CRYSTAL RIVER OCEAN BEACH MOUNTAIN FOREST STORM CLOUD NIGHT LIGHT DREAM " +
  "NORTH SOUTH EAST WEST CENTER KING QUEEN PRINCE KNIGHT CASTLE DRAGON SWORD MAGIC SPELL WIZARD " +
  "MUSIC DANCE SONG MOVIE BOOK STORY POEM PLAY GAME SPORT TEAM BALL GOAL SCORE " +
  "PHONE EMAIL MESSAGE MEDIA VIDEO PHOTO CAMERA SCREEN COMPUTER " +
  "MONEY POWER TRUTH JUSTICE PEACE FREEDOM ACCESS TOKEN SECRET MASTER PASSWORD PRIVATE PUBLIC " +
  "NETWORK SERVER SYSTEM BACKUP RECOVERY CORRECT HORSE BATTERY STAPLE PLEASE WINTER SUMMER " +
  "LONDON PARIS TOKYO BERLIN YORK CITY TOWN COUNTRY EARTH SPACE PLANET " +
  "BLACK WHITE GREEN YELLOW PURPLE BROWN ORANGE ANSWER QUICK BROWN JUMPS OVER LAZY " +
  "EXPRESS TRAIN PLANE CAKE PORTAL STYLE WAND WARS STAR PEPPER SALT SUGAR BREAD " +
  "SPHINX QUARTZ VORTEX CYBER SECURITY RAIN SPAIN FALLS BACK FRONT LEFT RIGHT " +
  "HUMAN HEART SPEAK FORCE NEVER THING HEAVEN " +
  "PART PRESS PORT HAND LAND HARD FIRE WIRE BALL CALL FALL BELL CELL BILL FILL " +
  "BEST REST WEST CASE BASE DARK MARK PARK DATE FATE GATE HATE LATE RATE " +
  "DEAL REAL SEAL DEAR FEAR HEAR NEAR YEAR DEEP KEEP FEED NEED SEED " +
  "FILE MILE TIME FINE LINE MINE NINE FIND KIND MIND FIRM FISH LIST " +
  "FLAG FLAT FLOW SLOW SHOW FOLD GOLD HOLD FOOD GOOD WOOD FOOL POOL FOOT ROOT " +
  "FORM FORT FOUR YOUR FREE TREE FROM FULL GAIN MAIN PAIN RAIN GAME NAME SAME " +
  "GATE GAVE GIFT GIRL GIVE GLAD GLOW GOAL GOLD GONE GOOD GRAB GRAY GREW GROW " +
  "HARD HARM HATE HAVE HEAD LEAD READ HEAL HEAR HEAT MEAT HELD HELP HERE HERO " +
  "HIDE RIDE SIDE WIDE HIGH HIKE LIKE HILL HINT HOLD HOLE HOME HOPE HORN HOST MOST " +
  "HOUR YOUR HUGE HUNT HURT IRON ITEM JOIN JUMP JUST KEEP KIND KING RING SING " +
  "LACK PACK LAKE MAKE TAKE LAND LANE LAST LATE LAZY LEAD LEAF LEAK PEAK WEAK " +
  "LEFT LEND SEND LESS LIFE WIFE LIFT LIKE LIME TIME LINE LINK LIST LIVE LOAD ROAD " +
  "LOCK LONG SONG LOOK TOOK LORD LOSE LOSS LOST LOUD LOVE LUCK MADE MAIL MAIN MAKE " +
  "MALE MANY MARK MASS MATE MATH MEAL MEAN MEAT MEET MELT MENU MESS MILE MILK MILL " +
  "MIND MINE MINT MISS MIST MODE MOOD MOON SOON MORE MOST MOVE MUCH MUST NAME NAVY " +
  "NEAR NEAT NECK NEED NEST NEWS NEXT NICE NINE NODE NONE NOSE ROSE NOTE VOTE ONCE " +
  "ONLY OPEN OVER PACE PACK PAGE PAID PAIN PAIR PALE PARK PART PASS PAST PATH PEAK " +
  "PICK PILE PINE PINK PIPE PLAN PLAY PLOT PLUS POEM POET POLE POND POOL POOR PORT " +
  "POSE POST PRAY PULL PUMP PURE PUSH RACE RACK RAGE RAID RAIL RAIN RANK RARE RATE " +
  "READ REAL REAR REED REEL RENT REST RICE RICH RIDE RING RISE RISK ROAD ROCK ROLE " +
  "ROLL ROOF ROOM ROOT ROPE ROSE RULE RUSH RUST SAFE SAID SAIL SALE SALT SAME SAND " +
  "SAVE SEAL SEAM SEAT SEED SEEK SEEM SEEN SELF SELL SEND SENT SHIP SHOP SHOT SHOW " +
  "SHUT SICK SIDE SIGN SILK SING SINK SITE SIZE SKIN SKIP SLIP SLOW SNOW SOAP SOFT " +
  "SOIL SOLD SOLE SOME SONG SOON SORE SORT SOUL SOUP SOUR SPAN STAR STAY STEM STEP " +
  "STOP SUCH SUIT SURE SURF SWIM TACK TAIL TAKE TALE TALK TALL TAME TANK TAPE TASK " +
  "TEAM TEAR TELL TEND TENT TERM TEST TEXT THAN THAT THEM THEN THEY THIN THIS TICK " +
  "TIDE TILE TILL TIME TIRE TOLD TOLL TONE TOOK TOOL TORN TOSS TOUR TOWN TRAP TRAY " +
  "TREE TRIM TRIP TRUE TUBE TUNE TURN TYPE UNIT UPON URGE USED USER VAIN VARY VASE " +
  "VAST VERY VEST VETO VIEW VINE VOID VOTE WAGE WAIT WAKE WALK WALL WAND WANT WARD " +
  "WARM WARN WASH WAVE WEAK WEAR WEEK WELL WENT WERE WEST WHAT WHEN WHIP WIDE WIFE " +
  "WILD WILL WIND WINE WING WIPE WIRE WISE WISH WITH WOOD WORD WORE WORK WORN WRAP " +
  "YEAR YELL YOUR ZERO ZONE WART PRESS GANG"
).split(/\s+/);

function buildOpenEnglishTokens(): ReadonlySet<string> {
  const out = new Set<string>();
  for (const raw of OPEN_ENGLISH_WORDS_RAW) {
    const w = raw.toUpperCase();
    if (w.length >= 4) out.add(w);
    // Crockford letter-only form (O→0/I,L→1/U→V then drop digits).
    const crock = w.replace(/O/g, "0").replace(/[IL]/g, "1").replace(/U/g, "V");
    let letters = "";
    for (const c of crock) {
      if (c >= "A" && c <= "Z") letters += c;
    }
    if (letters.length >= 4) out.add(letters);
  }
  return out;
}

const OPEN_ENGLISH_TOKENS: ReadonlySet<string> = buildOpenEnglishTokens();

/** Digit prefixes of well-known constants (π, e, √2) — not fib (already gated). */
const MATH_CONST_DIGIT_PREFIXES: readonly string[] = [
  "31415926535897932384626433832795",
  "27182818284590452353602874713526",
  "14142135623730950488016887242096",
];

/** Broader leet fold for open English / vowel analysis (Latin reconstruction). */
const ENGLISH_LEET_FOLD: Readonly<Record<string, string>> = {
  "0": "O",
  "1": "I",
  "2": "Z",
  "3": "E",
  "4": "A",
  "5": "S",
  "6": "G",
  "7": "T",
  "8": "B",
  "9": "G",
};

function latinLetterSkeleton(secret: string): string {
  let out = "";
  for (const c of secret) {
    if (c >= "A" && c <= "Z") out += c;
    else {
      const folded = ENGLISH_LEET_FOLD[c];
      if (folded !== undefined) out += folded;
    }
  }
  return out;
}

function maxDigitRun(secret: string): number {
  let max = 0;
  let run = 0;
  for (const c of secret) {
    if (c >= "0" && c <= "9") {
      run += 1;
      if (run > max) max = run;
    } else {
      run = 0;
    }
  }
  return max;
}

function digitHeadLength(secret: string): number {
  let n = 0;
  for (const c of secret) {
    if (c >= "0" && c <= "9") n += 1;
    else break;
  }
  return n;
}

/**
 * True when digits form a long run or embed a well-known math-constant prefix
 * (π / e / √2). Catches 314159265358979… that fib/step-k miss.
 */
function hasStructuredDigitConstant(secret: string): boolean {
  if (maxDigitRun(secret) >= RECOVERY_PACK_MAX_DIGIT_RUN) return true;
  if (digitHeadLength(secret) >= RECOVERY_PACK_MAX_DIGIT_RUN) return true;
  const digits = [...secret].filter((c) => c >= "0" && c <= "9").join("");
  if (digits.length < 8) return false;
  for (const prefix of MATH_CONST_DIGIT_PREFIXES) {
    for (let len = 8; len <= Math.min(digits.length, prefix.length); len++) {
      for (let i = 0; i <= digits.length - len; i++) {
        if (prefix.includes(digits.slice(i, i + len))) return true;
      }
    }
  }
  return false;
}

function englishCoverLetters(skel: string): number {
  const n = skel.length;
  if (n < 4) return 0;
  const dp = new Array<number>(n + 1).fill(0);
  for (let i = 0; i < n; i++) {
    if (dp[i]! > dp[i + 1]!) dp[i + 1] = dp[i]!;
    for (let len = 4; len <= Math.min(12, n - i); len++) {
      if (OPEN_ENGLISH_TOKENS.has(skel.slice(i, i + len))) {
        const next = dp[i]! + len;
        if (next > dp[i + len]!) dp[i + len] = next;
      }
    }
  }
  return dp[n]!;
}

function englishNgramHits(skel: string): { bigrams: number; trigrams: number } {
  let bigrams = 0;
  let trigrams = 0;
  for (let i = 0; i < skel.length - 1; i++) {
    if (OPEN_ENGLISH_BIGRAMS.has(skel.slice(i, i + 2))) bigrams += 1;
  }
  for (let i = 0; i < skel.length - 2; i++) {
    if (OPEN_ENGLISH_TRIGRAMS.has(skel.slice(i, i + 3))) trigrams += 1;
  }
  return { bigrams, trigrams };
}

function latinVowelFraction(skel: string): number {
  if (skel.length === 0) return 0;
  let v = 0;
  for (const c of skel) {
    if (c === "A" || c === "E" || c === "I" || c === "O" || c === "U" || c === "Y") v += 1;
  }
  return v / skel.length;
}

/** Year + KEY/ABC pad — the dominant hand-rolled ceremony mnemonic shape. */
function hasCeremonyMnemonicPad(secret: string): boolean {
  return /20[0-2]\d/.test(secret) && /(?:KEY|ABC)/.test(secret);
}

/**
 * True when the secret matches the residual human-pattern class beyond finite
 * dictionary lists: math digit constants, ceremony mnemonic pads, high-vowel
 * English-like letter skeletons, open n-gram density, or open-lexicon cover.
 */
function hasHumanPatternClass(secret: string): boolean {
  if (hasStructuredDigitConstant(secret)) return true;

  const letterSk = letterSkeleton(secret, false);
  const latinSk = latinLetterSkeleton(secret);
  const skeletons = [letterSk, latinSk];
  if (letterSk.length > 0) skeletons.push([...letterSk].reverse().join(""));
  if (latinSk.length > 0) skeletons.push([...latinSk].reverse().join(""));

  let cover = 0;
  let bigrams = 0;
  let trigrams = 0;
  for (const sk of skeletons) {
    const c = englishCoverLetters(sk);
    if (c > cover) cover = c;
    const ng = englishNgramHits(sk);
    if (ng.bigrams > bigrams) bigrams = ng.bigrams;
    if (ng.trigrams > trigrams) trigrams = ng.trigrams;
  }

  const letters = letterSk.length;
  const letterFrac = secret.length === 0 ? 0 : letters / secret.length;
  const vowelFrac = Math.max(latinVowelFraction(letterSk), latinVowelFraction(latinSk));

  if (
    hasCeremonyMnemonicPad(secret) &&
    letters >= RECOVERY_PACK_MIN_MNEMONIC_PAD_LETTERS &&
    letterFrac >= RECOVERY_PACK_MIN_MNEMONIC_PAD_LETTER_FRAC
  ) {
    return true;
  }
  if (
    vowelFrac >= RECOVERY_PACK_MAX_LATIN_VOWEL_FRAC &&
    letters >= RECOVERY_PACK_MIN_LETTERS_FOR_VOWEL_GUARD
  ) {
    return true;
  }
  if (trigrams >= RECOVERY_PACK_MAX_ENGLISH_TRIGRAM_HITS) return true;
  if (bigrams >= RECOVERY_PACK_MAX_ENGLISH_BIGRAM_HITS) return true;
  if (cover >= RECOVERY_PACK_MIN_ENGLISH_COVER_LETTERS) return true;
  if (
    cover >= RECOVERY_PACK_MIN_ENGLISH_COVER_WITH_VOWEL &&
    vowelFrac >= RECOVERY_PACK_MIN_VOWEL_FRAC_WITH_COVER
  ) {
    return true;
  }
  return false;
}

/**
 * Named reason the secret is unfit to seal a pack, or null when it passes.
 * The message names the rule that failed — it says nothing about any pack.
 *
 * Creation accepts only the generateRecoverySecret() shape (ZTR-1220): the
 * charset×length proxy that previously cleared long patterned / dictionary
 * phrases is not an accept path. Structure guards cover near-period tiles,
 * same-symbol / paired-double blocks, step-k and strided monotone runs, long
 * letter runs, class alternation / pair sequences, keyboard rows/columns/
 * diagonals, digit-broken + reversed dictionary skeletons, and the non-list
 * human-pattern class (math digit constants, ceremony mnemonic pads, high
 * Latin-vowel letter skeletons, open English n-grams, open-lexicon cover).
 */
export function recoverySecretWeakness(secret: string): string | null {
  if (secret.length === 0) return "recovery secret is required";
  if (secret.length > RECOVERY_PACK_SECRET_MAX_CHARS) {
    return `recovery secret must be at most ${RECOVERY_PACK_SECRET_MAX_CHARS} characters`;
  }
  if (DIGITS_ONLY_RE.test(secret)) {
    return "recovery secret must not be digits only — a numeric passcode is enumerable offline against the pack";
  }
  if (!SECRET_ALPHABET_RE.test(secret)) {
    return `recovery secret must be exactly ${RECOVERY_PACK_GENERATED_SECRET_CHARS} characters from the Crockford base32 alphabet (0-9 A-Z except I L O U) — use generateRecoverySecret()`;
  }
  if (new Set(secret).size < RECOVERY_PACK_MIN_DISTINCT_CHARS) {
    return `recovery secret must use at least ${RECOVERY_PACK_MIN_DISTINCT_CHARS} distinct characters`;
  }
  if (hasRepeatedStructure(secret)) {
    return "recovery secret must not be a repeated substring";
  }
  if (hasLongSameRun(secret)) {
    return "recovery secret must not contain a long same-character run";
  }
  if (hasMonotoneAlphabetRun(secret)) {
    return "recovery secret must not contain a long sequential run";
  }
  if (hasFibonacciDigitRun(secret)) {
    return "recovery secret must not contain a long sequential run";
  }
  if (hasLongLetterRun(secret)) {
    return "recovery secret must not contain a long letter-only run";
  }
  if (hasClassAlternationRun(secret)) {
    return "recovery secret must not contain a long digit/letter alternation";
  }
  if (hasClassPairRun(secret)) {
    return "recovery secret must not contain a long digit/letter pair sequence";
  }
  if (hasKeyboardRowRun(secret)) {
    return "recovery secret must not contain a keyboard-row sequence";
  }
  if (hasDictionarySkeleton(secret)) {
    return "recovery secret must not embed a dictionary or passphrase skeleton";
  }
  if (hasHumanPatternClass(secret)) {
    return "recovery secret must not be a low-entropy human pattern";
  }
  // Non-vacuous floor: i.i.d. Crockford×26 is 130 bits. Reject if the named
  // constants ever shrink the theoretical maximum below the floor — this is a
  // compile-time belt on the alphabet/length pair, not a per-secret estimate.
  // (estimateRecoverySecretEntropyBits stays diagnostics-only.)
  if (
    RECOVERY_PACK_GENERATED_SECRET_CHARS * Math.log2(RECOVERY_PACK_SECRET_ALPHABET.length) <
    RECOVERY_PACK_MIN_ENTROPY_BITS
  ) {
    return `recovery secret alphabet×length is below the ${RECOVERY_PACK_MIN_ENTROPY_BITS}-bit floor`;
  }
  return null;
}

/** Shape check for a secret offered on the *open* path — v1 packs are digits. */
export function isAcceptableRecoverySecretShape(secret: string): boolean {
  return secret.length > 0 && secret.length <= RECOVERY_PACK_SECRET_MAX_CHARS;
}

/**
 * The sanctioned way to obtain a pack secret: generate, never accept. Each symbol
 * is an independent CSPRNG draw from a 32-symbol alphabet, so the estimator above
 * agrees exactly with the true entropy (130 bits).
 */
export function generateRecoverySecret(): string {
  // A draw can in principle land under the distinct-character / structure
  // guards; redraw rather than emit a secret the creation path would refuse.
  // 64 attempts: letter-run redraw rate is a few percent; 8 was too tight after
  // the Review B structure floor tightened (near-period / step-k / letter-run).
  for (let attempt = 0; attempt < 64; attempt++) {
    let out = "";
    for (let i = 0; i < RECOVERY_PACK_GENERATED_SECRET_CHARS; i++) {
      out += RECOVERY_PACK_SECRET_ALPHABET[randomInt(0, RECOVERY_PACK_SECRET_ALPHABET.length)];
    }
    if (recoverySecretWeakness(out) === null) return out;
  }
  throw new RecoveryPackError("weak_secret", "recovery secret generation failed");
}

function wipe(buf: Uint8Array | Buffer | undefined): void {
  if (buf === undefined) return;
  buf.fill(0);
}

function b64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function b64urlDecode(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function deriveKey(secret: string, salt: Uint8Array): Uint8Array {
  const passBytes = Buffer.from(secret, "utf8");
  try {
    return argon2id(passBytes, salt, {
      m: RECOVERY_PACK_KDF.memory_kib,
      t: RECOVERY_PACK_KDF.iterations,
      p: RECOVERY_PACK_KDF.parallelism,
      dkLen: RECOVERY_PACK_KDF.hash_len,
    });
  } finally {
    wipe(passBytes);
  }
}

/**
 * Build a recovery pack file (UTF-8 JSON bytes). Caller supplies vault master;
 * this never logs it. Zeroizes derived key material before return.
 *
 * Generate-only (ZTR-1220 r6): the seal secret is always a server-side CSPRNG
 * draw via generateRecoverySecret(). Caller-supplied secrets are refused so a
 * hand-rolled mnemonic cannot weaken custody even when it clears structure
 * heuristics. Once the artifact exists the seal is fixed.
 */
export function createRecoveryPack(input: {
  readonly vaultMasterKey: string;
  /**
   * Forbidden on the production seal path. Present only so a mistaken caller
   * gets an explicit refusal rather than silent ignore.
   */
  readonly secret?: string;
  /** Test hook — fixed salt (must be ≥16 bytes). */
  readonly salt?: Uint8Array;
  /** Test hook — fixed 12-byte nonce. */
  readonly nonce?: Uint8Array;
}): {
  readonly envelope: RecoveryPackEnvelope;
  readonly fileBytes: Buffer;
  /** The secret the pack is sealed under — show once, never persist. */
  readonly secret: string;
} {
  if (input.secret !== undefined) {
    throw new RecoveryPackError(
      "caller_supplied_secret",
      "recovery pack create is generate-only — do not supply recovery_secret; the node seals under a CSPRNG secret and returns it once",
    );
  }
  return sealRecoveryPack({
    vaultMasterKey: input.vaultMasterKey,
    secret: generateRecoverySecret(),
    salt: input.salt,
    nonce: input.nonce,
  });
}

/**
 * Test / fixture seal under a fixed secret that already clears
 * recoverySecretWeakness. Production create/reissue never call this.
 */
export function createRecoveryPackForTests(input: {
  readonly vaultMasterKey: string;
  readonly secret: string;
  readonly salt?: Uint8Array;
  readonly nonce?: Uint8Array;
}): {
  readonly envelope: RecoveryPackEnvelope;
  readonly fileBytes: Buffer;
  readonly secret: string;
} {
  const weakness = recoverySecretWeakness(input.secret);
  if (weakness !== null) {
    throw new RecoveryPackError("weak_secret", weakness);
  }
  return sealRecoveryPack({
    vaultMasterKey: input.vaultMasterKey,
    secret: input.secret,
    salt: input.salt,
    nonce: input.nonce,
  });
}

function sealRecoveryPack(input: {
  readonly vaultMasterKey: string;
  readonly secret: string;
  readonly salt?: Uint8Array;
  readonly nonce?: Uint8Array;
}): {
  readonly envelope: RecoveryPackEnvelope;
  readonly fileBytes: Buffer;
  readonly secret: string;
} {
  const secret = input.secret;
  if (input.vaultMasterKey.length < 32) {
    throw new RecoveryPackError(
      "master_key_too_short",
      "vault_master_key must be at least 32 characters",
    );
  }

  const salt = input.salt
    ? Uint8Array.from(input.salt)
    : new Uint8Array(randomBytes(RECOVERY_PACK_SALT_BYTES));
  if (salt.byteLength < RECOVERY_PACK_SALT_BYTES) {
    throw new RecoveryPackError("invalid_format", "salt must be ≥128-bit");
  }
  const nonce = input.nonce
    ? Buffer.from(input.nonce)
    : randomBytes(RECOVERY_PACK_NONCE_BYTES);
  if (nonce.byteLength !== RECOVERY_PACK_NONCE_BYTES) {
    throw new RecoveryPackError("invalid_format", "nonce must be 12 bytes");
  }

  const payload: RecoveryPackSecretPayload = {
    v: RECOVERY_PACK_PAYLOAD_VERSION,
    vault_master_key: input.vaultMasterKey,
  };
  // Byte-exact JSON.stringify of fixed key sequence (the byte-exact signing rule).
  const plaintext = Buffer.from(
    JSON.stringify({ v: payload.v, vault_master_key: payload.vault_master_key }),
    "utf8",
  );

  let key: Uint8Array | undefined;
  let keyBuf: Buffer | undefined;
  try {
    key = deriveKey(secret, salt);
    keyBuf = Buffer.from(key);
    const cipher = createCipheriv("aes-256-gcm", keyBuf, nonce);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const ciphertext = Buffer.concat([ct, tag]);

    const envelope: RecoveryPackEnvelope = {
      format: RECOVERY_PACK_FORMAT,
      kdf: {
        alg: "argon2id",
        salt_b64url: b64urlEncode(salt),
        memory_kib: RECOVERY_PACK_KDF.memory_kib,
        iterations: RECOVERY_PACK_KDF.iterations,
        parallelism: RECOVERY_PACK_KDF.parallelism,
        hash_len: RECOVERY_PACK_KDF.hash_len,
      },
      aead: {
        alg: RECOVERY_PACK_AEAD_ALG,
        nonce_b64url: b64urlEncode(nonce),
      },
      ciphertext_b64url: b64urlEncode(ciphertext),
      pack_content_sha256: sha256Hex(ciphertext),
    };

    // Pretty-print not used — compact JSON for stable download bytes.
    const fileBytes = Buffer.from(JSON.stringify(envelope), "utf8");
    return { envelope, fileBytes, secret };
  } finally {
    wipe(plaintext);
    wipe(key);
    wipe(keyBuf);
    wipe(salt);
    wipe(nonce);
  }
}

/**
 * Decrypt a pack file. Returns master key on success; throws RecoveryPackError
 * on any failure (generic — no decrypt oracle). Zeroizes KDF/AEAD key material.
 *
 * A v1 payload is never silently reinterpreted: it opens only when the caller
 * passes `allowLegacyV1`, and the returned `v` reports which path was taken.
 * The floor is deliberately NOT enforced here — a legacy pack legitimately
 * carries a digit passcode, and refusing to open it would strand the operator.
 */
export function openRecoveryPack(input: {
  readonly fileBytes: Uint8Array | string;
  readonly secret: string;
  /** Explicit opt-in to the superseded digit-passcode pack. */
  readonly allowLegacyV1?: boolean;
}): RecoveryPackSecretPayload {
  if (!isAcceptableRecoverySecretShape(input.secret)) {
    throw new RecoveryPackError(
      "invalid_passcode",
      `recovery secret must be 1–${RECOVERY_PACK_SECRET_MAX_CHARS} characters`,
    );
  }

  let parsed: unknown;
  try {
    const text =
      typeof input.fileBytes === "string"
        ? input.fileBytes
        : Buffer.from(input.fileBytes).toString("utf8");
    parsed = JSON.parse(text);
  } catch {
    throw new RecoveryPackError("invalid_format", "recovery pack is not valid JSON");
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new RecoveryPackError("invalid_format", "recovery pack envelope invalid");
  }
  const env = parsed as Record<string, unknown>;
  if (env.format !== RECOVERY_PACK_FORMAT && env.format !== RECOVERY_PACK_FORMAT_LEGACY_V1) {
    throw new RecoveryPackError("invalid_format", "unknown recovery pack format");
  }

  const kdf = env.kdf as Record<string, unknown> | undefined;
  const aead = env.aead as Record<string, unknown> | undefined;
  if (
    kdf === undefined ||
    aead === undefined ||
    typeof env.ciphertext_b64url !== "string" ||
    typeof env.pack_content_sha256 !== "string"
  ) {
    throw new RecoveryPackError("invalid_format", "recovery pack missing fields");
  }
  if (
    kdf.alg !== "argon2id" ||
    kdf.memory_kib !== RECOVERY_PACK_KDF.memory_kib ||
    kdf.iterations !== RECOVERY_PACK_KDF.iterations ||
    kdf.parallelism !== RECOVERY_PACK_KDF.parallelism ||
    kdf.hash_len !== RECOVERY_PACK_KDF.hash_len ||
    typeof kdf.salt_b64url !== "string"
  ) {
    throw new RecoveryPackError("invalid_format", "recovery pack kdf rejected");
  }
  if (aead.alg !== RECOVERY_PACK_AEAD_ALG || typeof aead.nonce_b64url !== "string") {
    throw new RecoveryPackError("invalid_format", "recovery pack aead rejected");
  }

  let salt: Buffer | undefined;
  let nonce: Buffer | undefined;
  let ciphertext: Buffer | undefined;
  let key: Uint8Array | undefined;
  let keyBuf: Buffer | undefined;
  let plaintext: Buffer | undefined;

  try {
    salt = b64urlDecode(kdf.salt_b64url);
    nonce = b64urlDecode(aead.nonce_b64url);
    ciphertext = b64urlDecode(env.ciphertext_b64url);

    if (salt.byteLength < RECOVERY_PACK_SALT_BYTES) {
      throw new RecoveryPackError("invalid_format", "salt too short");
    }
    if (nonce.byteLength !== RECOVERY_PACK_NONCE_BYTES) {
      throw new RecoveryPackError("invalid_format", "nonce length invalid");
    }
    if (ciphertext.byteLength <= RECOVERY_PACK_TAG_BYTES) {
      throw new RecoveryPackError("invalid_format", "ciphertext too short");
    }

    const claimedSha = String(env.pack_content_sha256).toLowerCase();
    const actualSha = sha256Hex(ciphertext);
    const a = Buffer.from(claimedSha, "utf8");
    const b = Buffer.from(actualSha, "utf8");
    if (a.byteLength !== b.byteLength || !timingSafeEqual(a, b)) {
      throw new RecoveryPackError("invalid_format", "pack content digest mismatch");
    }

    const tag = ciphertext.subarray(ciphertext.byteLength - RECOVERY_PACK_TAG_BYTES);
    const ct = ciphertext.subarray(0, ciphertext.byteLength - RECOVERY_PACK_TAG_BYTES);

    key = deriveKey(input.secret, salt);
    keyBuf = Buffer.from(key);
    const decipher = createDecipheriv("aes-256-gcm", keyBuf, nonce);
    decipher.setAuthTag(tag);
    try {
      plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
    } catch {
      throw new RecoveryPackError("decrypt_failed", "recovery pack decrypt failed");
    }

    let payload: unknown;
    try {
      payload = JSON.parse(plaintext.toString("utf8"));
    } catch {
      throw new RecoveryPackError("invalid_payload", "recovery pack payload invalid");
    }
    if (
      payload === null ||
      typeof payload !== "object" ||
      Array.isArray(payload) ||
      typeof (payload as { vault_master_key?: unknown }).vault_master_key !== "string"
    ) {
      throw new RecoveryPackError("invalid_payload", "recovery pack payload shape invalid");
    }
    // Payload version is authoritative — it is inside the AEAD, the outer
    // `format` label is not. Relabelling a v1 file as v2 lands here, not past it.
    const version = (payload as { v?: unknown }).v;
    if (version !== RECOVERY_PACK_PAYLOAD_VERSION && version !== 1) {
      throw new RecoveryPackError("invalid_payload", "recovery pack payload shape invalid");
    }
    if (version === 1 && input.allowLegacyV1 !== true) {
      throw new RecoveryPackError(
        "legacy_pack_v1",
        "this is a superseded v1 recovery pack sealed under a digit passcode — restore it only through the explicit legacy path, then re-issue and destroy it",
      );
    }
    const master = (payload as { vault_master_key: string }).vault_master_key;
    if (master.length < 32) {
      throw new RecoveryPackError("invalid_payload", "vault_master_key too short");
    }
    return { v: version === 1 ? 1 : RECOVERY_PACK_PAYLOAD_VERSION, vault_master_key: master };
  } finally {
    wipe(salt);
    wipe(nonce);
    wipe(ciphertext);
    wipe(key);
    wipe(keyBuf);
    wipe(plaintext);
  }
}

/**
 * Re-seal an existing pack as v2. The master never leaves this call — it is the
 * only way to replace a compromised-if-leaked v1 artifact without the operator
 * handling the raw vault master key. The replacement seal secret is always
 * generate-only (ZTR-1220 r6) — same policy as createRecoveryPack.
 */
export function reissueRecoveryPack(input: {
  readonly fileBytes: Uint8Array | string;
  /** Secret the *existing* pack is sealed under (a v1 digit passcode is fine). */
  readonly secret: string;
  /**
   * Forbidden on the production re-issue path. Present so a mistaken caller
   * gets an explicit refusal rather than silent ignore.
   */
  readonly newSecret?: string;
  /** Explicit opt-in when the existing pack is v1. */
  readonly allowLegacyV1?: boolean;
  /** Test hook — fixed salt (must be ≥16 bytes). */
  readonly salt?: Uint8Array;
  /** Test hook — fixed 12-byte nonce. */
  readonly nonce?: Uint8Array;
}): {
  readonly envelope: RecoveryPackEnvelope;
  readonly fileBytes: Buffer;
  /** The secret the *new* pack is sealed under — show once, never persist. */
  readonly secret: string;
  /** Payload version of the pack that was replaced. */
  readonly previousVersion: 1 | 2;
  readonly previousPackContentSha256: string | null;
} {
  if (input.newSecret !== undefined) {
    throw new RecoveryPackError(
      "caller_supplied_secret",
      "recovery pack re-issue is generate-only — do not supply a replacement secret; the node seals under a CSPRNG secret and returns it once",
    );
  }
  const previousPackContentSha256 = peekPackContentSha256(input.fileBytes);
  const opened = openRecoveryPack({
    fileBytes: input.fileBytes,
    secret: input.secret,
    allowLegacyV1: input.allowLegacyV1,
  });
  const holder = { master: opened.vault_master_key };
  try {
    const built = createRecoveryPack({
      vaultMasterKey: holder.master,
      salt: input.salt,
      nonce: input.nonce,
    });
    return { ...built, previousVersion: opened.v, previousPackContentSha256 };
  } finally {
    holder.master = "";
  }
}

/** Extract pack_content_sha256 from file bytes without decrypting (audit only). */
export function peekPackContentSha256(fileBytes: Uint8Array | string): string | null {
  try {
    const text =
      typeof fileBytes === "string" ? fileBytes : Buffer.from(fileBytes).toString("utf8");
    const parsed = JSON.parse(text) as { pack_content_sha256?: unknown };
    if (typeof parsed.pack_content_sha256 === "string" && /^[0-9a-f]{64}$/i.test(parsed.pack_content_sha256)) {
      return parsed.pack_content_sha256.toLowerCase();
    }
    return null;
  } catch {
    return null;
  }
}
