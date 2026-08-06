import { BigNumber } from "bignumber.js";
import { describe, expect, it } from "vitest";
import {
  addAmounts,
  compareAmounts,
  emitAmount,
  isFiniteAmount,
  isNumericallyPositive,
  isWithinBalanceMagnitude,
  isWithinOperationMagnitude,
  numericDecimalPlaces,
  subtractAmounts,
} from "./emitter.js";
import { enforceAmountField, type AmountFieldEnforcement } from "./enforcement.js";
import { AMOUNT_FIELD_ROLES, type AmountFieldRole } from "./field-roles.js";
import { inspectForeignAmount, type ForeignAmountInspection } from "./foreign.js";
import { matchesCanonicalGrammar } from "./grammar.js";
import { AMOUNT_REJECTION_REASONS } from "./manifest.js";
import {
  AMOUNT_INPUT_TYPE_ERROR_MESSAGE,
  assertPrimitiveAmountString,
} from "./string-boundary.js";
import {
  isCanonicalAmount,
  validateBalanceAmount,
  validateOperationAmount,
  type AmountCheck,
} from "./validators.js";

type GuardedCall = {
  readonly label: string;
  readonly call: (value: unknown) => unknown;
};

const inspectionCalls: readonly GuardedCall[] = [
  { label: "matchesCanonicalGrammar", call: matchesCanonicalGrammar },
  { label: "isFiniteAmount", call: isFiniteAmount },
  { label: "numericDecimalPlaces", call: numericDecimalPlaces },
  { label: "isNumericallyPositive", call: isNumericallyPositive },
  { label: "isWithinBalanceMagnitude", call: isWithinBalanceMagnitude },
  { label: "isWithinOperationMagnitude", call: isWithinOperationMagnitude },
  { label: "isCanonicalAmount", call: isCanonicalAmount },
  { label: "validateBalanceAmount", call: validateBalanceAmount },
  { label: "validateOperationAmount", call: validateOperationAmount },
  { label: "inspectForeignAmount", call: inspectForeignAmount },
];

const roles = Object.keys(AMOUNT_FIELD_ROLES) as AmountFieldRole[];
const guardedCalls: readonly GuardedCall[] = [
  { label: "assertPrimitiveAmountString", call: assertPrimitiveAmountString },
  ...inspectionCalls,
  ...roles.map((role) => ({
    label: `enforceAmountField(${role})`,
    call: (value: unknown) => enforceAmountField(role, value),
  })),
];

type RejectedInput = {
  readonly value: unknown;
  readonly activity: () => number;
};

type RejectedInputCase = {
  readonly label: string;
  readonly create: () => RejectedInput;
};

function inert(value: unknown): RejectedInput {
  return { value, activity: () => 0 };
}

function coercibleObject(): RejectedInput {
  let hooks = 0;
  return {
    value: {
      [Symbol.toPrimitive]() {
        hooks += 1;
        return "2.5";
      },
      toString() {
        hooks += 1;
        return "2.5";
      },
      valueOf() {
        hooks += 1;
        return 2.5;
      },
    },
    activity: () => hooks,
  };
}

function throwingGetter(property: typeof Symbol.toPrimitive | "toString" | "valueOf"): RejectedInput {
  let hooks = 0;
  const value = Object.create(null) as Record<PropertyKey, unknown>;
  Object.defineProperty(value, property, {
    get() {
      hooks += 1;
      throw new Error("amount coercion hook must not run");
    },
  });
  return { value, activity: () => hooks };
}

function trapCounter<T extends object>(target: T, revoked = false): RejectedInput {
  let traps = 0;
  const trap = (): never => {
    traps += 1;
    throw new Error("amount proxy trap must not run");
  };
  const handler: ProxyHandler<T> = {
    apply: trap,
    construct: trap,
    defineProperty: trap,
    deleteProperty: trap,
    get: trap,
    getOwnPropertyDescriptor: trap,
    getPrototypeOf: trap,
    has: trap,
    isExtensible: trap,
    ownKeys: trap,
    preventExtensions: trap,
    set: trap,
    setPrototypeOf: trap,
  };
  const revocable = Proxy.revocable(target, handler);
  if (revoked) revocable.revoke();
  return { value: revocable.proxy, activity: () => traps };
}

const rejectedInputs: readonly RejectedInputCase[] = [
  { label: "zero number", create: () => inert(0) },
  { label: "fractional number", create: () => inert(2.5) },
  { label: "unsafe integer number", create: () => inert(Number.MAX_SAFE_INTEGER + 1) },
  { label: "NaN", create: () => inert(Number.NaN) },
  { label: "positive infinity", create: () => inert(Number.POSITIVE_INFINITY) },
  { label: "negative infinity", create: () => inert(Number.NEGATIVE_INFINITY) },
  { label: "negative zero", create: () => inert(-0) },
  { label: "bigint", create: () => inert(25n) },
  { label: "true", create: () => inert(true) },
  { label: "false", create: () => inert(false) },
  { label: "null", create: () => inert(null) },
  { label: "undefined", create: () => inert(undefined) },
  { label: "boxed string", create: () => inert(new String("2.5")) },
  { label: "array", create: () => inert(["2.5"]) },
  { label: "symbol", create: () => inert(Symbol("2.5")) },
  { label: "BigNumber", create: () => inert(new BigNumber("2.5")) },
  { label: "plain coercible object", create: coercibleObject },
  {
    label: "throwing Symbol.toPrimitive getter",
    create: () => throwingGetter(Symbol.toPrimitive),
  },
  { label: "throwing toString getter", create: () => throwingGetter("toString") },
  { label: "throwing valueOf getter", create: () => throwingGetter("valueOf") },
  { label: "object proxy", create: () => trapCounter({}) },
  { label: "callable proxy", create: () => trapCounter(function amountCallable() {}) },
  { label: "revoked proxy", create: () => trapCounter({}, true) },
];

function thrownBy(call: () => unknown): unknown {
  try {
    call();
  } catch (error) {
    return error;
  }
  return undefined;
}

describe("primitive-string boundary — every public inspection root", () => {
  for (const guardedCall of guardedCalls) {
    it(`${guardedCall.label} rejects all non-primitive strings without observation`, () => {
      for (const rejectedInput of rejectedInputs) {
        const input = rejectedInput.create();
        const context = `${guardedCall.label} / ${rejectedInput.label}`;
        const error = thrownBy(() => guardedCall.call(input.value));

        expect(error, context).toBeInstanceOf(TypeError);
        expect((error as TypeError).message, context).toBe(AMOUNT_INPUT_TYPE_ERROR_MESSAGE);
        expect(input.activity(), context).toBe(0);
      }
    });
  }

  it("guards amount before observing a hostile field role", () => {
    let amountHooks = 0;
    const amount = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(amount, Symbol.toPrimitive, {
      get() {
        amountHooks += 1;
        throw new Error("amount hook must not run");
      },
    });

    const roleInput = trapCounter({});
    const hostileRole = roleInput.value as AmountFieldRole;
    const error = thrownBy(() => enforceAmountField(hostileRole, amount));

    expect(error).toBeInstanceOf(TypeError);
    expect((error as TypeError).message).toBe(AMOUNT_INPUT_TYPE_ERROR_MESSAGE);
    expect(amountHooks).toBe(0);
    expect(roleInput.activity()).toBe(0);
  });
});

const OVERPRECISION = `0.${"1".repeat(33)}`;
const GREATEST_LEGAL = `99999999.${"9".repeat(32)}`;

type StringResultCase = {
  readonly label: string;
  readonly input: string;
  readonly grammar: boolean;
  readonly finite: boolean;
  readonly decimalPlaces: number | null;
  readonly positive: boolean;
  readonly balanceMagnitude: boolean;
  readonly operationMagnitude: boolean;
  readonly canonical: boolean;
  readonly balance: AmountCheck;
  readonly operation: AmountCheck;
  readonly foreign: ForeignAmountInspection;
};

const stringResults: readonly StringResultCase[] = [
  {
    label: "canonical",
    input: "2.5",
    grammar: true,
    finite: true,
    decimalPlaces: 1,
    positive: true,
    balanceMagnitude: true,
    operationMagnitude: true,
    canonical: true,
    balance: { ok: true, canonical: "2.5" },
    operation: { ok: true, canonical: "2.5" },
    foreign: { bytes: "2.5", wellFormed: true, anomaly: null },
  },
  {
    label: "non-canonical",
    input: "2.50",
    grammar: true,
    finite: true,
    decimalPlaces: 1,
    positive: true,
    balanceMagnitude: true,
    operationMagnitude: true,
    canonical: false,
    balance: { ok: false, reason: AMOUNT_REJECTION_REASONS.nonCanonical },
    operation: { ok: false, reason: AMOUNT_REJECTION_REASONS.nonCanonical },
    foreign: { bytes: "2.50", wellFormed: true, anomaly: null },
  },
  {
    label: "exponent",
    input: "1e5",
    grammar: false,
    finite: true,
    decimalPlaces: 0,
    positive: true,
    balanceMagnitude: true,
    operationMagnitude: true,
    canonical: false,
    balance: { ok: false, reason: AMOUNT_REJECTION_REASONS.grammar },
    operation: { ok: false, reason: AMOUNT_REJECTION_REASONS.grammar },
    foreign: {
      bytes: "1e5",
      wellFormed: false,
      anomaly: "foreign_amount_grammar_violation",
    },
  },
  {
    label: "negative",
    input: "-1",
    grammar: false,
    finite: true,
    decimalPlaces: 0,
    positive: false,
    balanceMagnitude: false,
    operationMagnitude: false,
    canonical: false,
    balance: { ok: false, reason: AMOUNT_REJECTION_REASONS.grammar },
    operation: { ok: false, reason: AMOUNT_REJECTION_REASONS.grammar },
    foreign: {
      bytes: "-1",
      wellFormed: false,
      anomaly: "foreign_amount_grammar_violation",
    },
  },
  {
    label: "zero",
    input: "0",
    grammar: true,
    finite: true,
    decimalPlaces: 0,
    positive: false,
    balanceMagnitude: true,
    operationMagnitude: false,
    canonical: true,
    balance: { ok: true, canonical: "0" },
    operation: { ok: false, reason: AMOUNT_REJECTION_REASONS.notPositive },
    foreign: { bytes: "0", wellFormed: true, anomaly: null },
  },
  {
    label: "overprecision",
    input: OVERPRECISION,
    grammar: false,
    finite: true,
    decimalPlaces: 33,
    positive: true,
    balanceMagnitude: false,
    operationMagnitude: false,
    canonical: false,
    balance: { ok: false, reason: AMOUNT_REJECTION_REASONS.grammar },
    operation: { ok: false, reason: AMOUNT_REJECTION_REASONS.grammar },
    foreign: {
      bytes: OVERPRECISION,
      wellFormed: false,
      anomaly: "foreign_amount_grammar_violation",
    },
  },
  {
    label: "exclusive bound",
    input: "100000000",
    grammar: false,
    finite: true,
    decimalPlaces: 0,
    positive: true,
    balanceMagnitude: false,
    operationMagnitude: false,
    canonical: false,
    balance: { ok: false, reason: AMOUNT_REJECTION_REASONS.grammar },
    operation: { ok: false, reason: AMOUNT_REJECTION_REASONS.grammar },
    foreign: {
      bytes: "100000000",
      wellFormed: false,
      anomaly: "foreign_amount_grammar_violation",
    },
  },
  {
    label: "greatest legal",
    input: GREATEST_LEGAL,
    grammar: true,
    finite: true,
    decimalPlaces: 32,
    positive: true,
    balanceMagnitude: true,
    operationMagnitude: true,
    canonical: true,
    balance: { ok: true, canonical: GREATEST_LEGAL },
    operation: { ok: true, canonical: GREATEST_LEGAL },
    foreign: { bytes: GREATEST_LEGAL, wellFormed: true, anomaly: null },
  },
];

function expectedEnforcement(
  role: AmountFieldRole,
  result: StringResultCase,
): AmountFieldEnforcement {
  const spec = AMOUNT_FIELD_ROLES[role];
  if (spec.authorship === "foreign") {
    return { kind: "foreign", role, ...result.foreign };
  }

  const check = spec.layer === "operation" ? result.operation : result.balance;
  if (check.ok) return { kind: "accepted", role, canonical: check.canonical };
  return { kind: "rejected", role, layer: spec.layer, reason: check.reason, value: result.input };
}

describe("primitive strings — all pre-boundary results stay byte-for-byte unchanged", () => {
  for (const result of stringResults) {
    it(`preserves the ${result.label} result matrix`, () => {
      expect(assertPrimitiveAmountString(result.input)).toBeUndefined();
      expect(matchesCanonicalGrammar(result.input)).toBe(result.grammar);
      expect(isFiniteAmount(result.input)).toBe(result.finite);
      expect(numericDecimalPlaces(result.input)).toBe(result.decimalPlaces);
      expect(isNumericallyPositive(result.input)).toBe(result.positive);
      expect(isWithinBalanceMagnitude(result.input)).toBe(result.balanceMagnitude);
      expect(isWithinOperationMagnitude(result.input)).toBe(result.operationMagnitude);
      expect(isCanonicalAmount(result.input)).toBe(result.canonical);
      expect(validateBalanceAmount(result.input)).toEqual(result.balance);
      expect(validateOperationAmount(result.input)).toEqual(result.operation);
      expect(inspectForeignAmount(result.input)).toEqual(result.foreign);

      for (const role of roles) {
        expect(enforceAmountField(role, result.input)).toEqual(expectedEnforcement(role, result));
      }
    });
  }

  it("rejects BigNumber at every public amount API — inspection, construction, and arithmetic", () => {
    const amount = new BigNumber("2.5");
    const other = new BigNumber("0.5");
    for (const inspectionCall of inspectionCalls) {
      const error = thrownBy(() => inspectionCall.call(amount));
      expect(error, inspectionCall.label).toBeInstanceOf(TypeError);
      expect((error as TypeError).message, inspectionCall.label).toBe(
        AMOUNT_INPUT_TYPE_ERROR_MESSAGE,
      );
    }

    // Construction and arithmetic reject BigNumber too: consolidated onto the #778 runtime
    // guard, the earlier `BigNumber.Value` passthrough is overturned and must never return.
    // `Reflect.apply` steps past the (now correct) primitive-string signatures to reach the
    // runtime guard, matching the frozen idiom in emitter.test.ts.
    const constructionCalls: readonly GuardedCall[] = [
      { label: "emitAmount", call: (value) => Reflect.apply(emitAmount, undefined, [value]) },
      { label: "addAmounts", call: (value) => Reflect.apply(addAmounts, undefined, [value, other]) },
      {
        label: "subtractAmounts",
        call: (value) => Reflect.apply(subtractAmounts, undefined, [value, other]),
      },
      {
        label: "compareAmounts",
        call: (value) => Reflect.apply(compareAmounts, undefined, [value, other]),
      },
    ];
    for (const constructionCall of constructionCalls) {
      const error = thrownBy(() => constructionCall.call(amount));
      expect(error, constructionCall.label).toBeInstanceOf(TypeError);
      expect((error as TypeError).message, constructionCall.label).toBe(
        AMOUNT_INPUT_TYPE_ERROR_MESSAGE,
      );
    }
  });
});
