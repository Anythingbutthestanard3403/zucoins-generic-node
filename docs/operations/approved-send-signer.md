# APPROVED sends stall without NODE_IDENTITY signer (ZTR-1231)

## Symptom

An external send is `APPROVED` (operator or auto-approve) but never reaches
`AWAITING_REDEMPTION`. Implementer polls show no formation. No recovery action
appears on the row.

## Cause

Money workers skip post-approve formation when signer boundary deps cannot be
built — typically:

- `NODE_IDENTITY` sealed-store signer not armed (missing/invalid `NODE_IDENTITY_SEED`
  at boot, or vault not opened), or
- this process does not hold signer leadership.

The worker logs at **error** level:

`skip SEND form for N APPROVED — signer deps unavailable`

and raises a throttled operator alert (`signer_loss` P1 via
`OPERATOR_ALERT_WEBHOOK_URL` when configured), at most once per five minutes.

## Operator response

1. Confirm `/health/ready` and leadership on this instance.
2. Confirm vault open and NODE_IDENTITY key retained for this `NODE_ID`.
3. Fix env / arm signer; formation resumes on the next money-worker tick without
   re-approval.
4. Do **not** re-approve or manually mutate status to force formation.

## Related

- Money admission also refuses new money when `eventSignerAvailable` is false
  (EVENT_SIGNING). That is a separate gate from NODE_IDENTITY formation signing.
