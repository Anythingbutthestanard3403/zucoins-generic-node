// Re-export shim — implementation lives in protocol/ so receive and verifier share one
// Inner-shape narrow. Do not re-derive foreign-scalar gates here.
export {
  SPLIT_CHAIN_INNER_OPTIONAL_FIELDS,
  SPLIT_CHAIN_INNER_REQUIRED_FIELDS,
  narrowSplitChainInner,
  type InnerShapeNarrowing,
  type InnerShapeRejection,
  type SplitChainInnerParseInput,
} from "../protocol/inner-shape.js";
