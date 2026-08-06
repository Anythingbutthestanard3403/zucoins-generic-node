export const AMOUNT_INPUT_TYPE_ERROR_MESSAGE = "ZKZ amount input must be a primitive string";

export function assertPrimitiveAmountString(value: unknown): asserts value is string {
  if (typeof value !== "string") {
    throw new TypeError(AMOUNT_INPUT_TYPE_ERROR_MESSAGE);
  }
}
