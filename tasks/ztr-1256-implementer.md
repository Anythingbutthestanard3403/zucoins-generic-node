# ZTR-1256 implementer

- **lane:** implementer · run=`13a1ca32-1790-481d-aa2f-c8b907a12c19`
- **branch:** `ztr-1256-approve-inbox-device-sign`

## Done

1. Shared `signApproveChallengePreimage` + availability helper (`approve-device-sign.ts`); TransferDetail + ApproveInbox use it.
2. Inbox approve posts real `device_key_id` / `device_signature` (held across TOTP re-prompts).
3. No local device → disabled Approve + link to `/devices` (no post-TOTP failure).
4. `formatApproveFailure` surfaces `same_operator_both_sides` and actionable copy for stale/device/challenge cases.

## AC

- [x] Enrolled device: inbox approve sends device fields (unit)
- [x] Distinct failure copy for dual-control same operator
- [x] No device → disabled + enrolment link
- [x] Tests cover device sign path
