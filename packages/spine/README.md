# nott-spine

Shared content-reference types for nBROWSER: capture frames, origin metadata
and the wire enums for source, origin, retention, taint and receipt rung.
They do not grant authority and cannot represent a witnessed result.

## Provides

- `CaptureFrame`, `OriginMetadata` and the wire enums `SourceCapability`, `OriginKind`, `TaintClass`, `RetentionPolicy`, `ReceiptRung`.
- Two typed error families: `ContractError` and `AuthorityError`.

## Validation boundaries

Capture dimensions are positive integers from 1 through 8192 inclusive.
`EmptyViewport` refuses booleans and floating-point dimensions, and
`ViewportTooLarge` refuses oversized integers. DPR accepts finite integers or floats in
`[1, 3]`, excluding booleans, and refuses invalid values with
`InvalidDevicePixelRatio`.

Origin metadata requires a real capture frame for browser captures and allowed
root files, including direct construction. Bounded text must be valid UTF-8
and retain its original typed refusal for invalid text.

## Ceilings & Does Not Provide

- **Authority Granting**: The types carry policy metadata. They do not grant permissions or execute actions.
