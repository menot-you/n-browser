# nott-spine

Shared content-reference types for nBROWSER: digest-bound references that carry
source, origin, retention and taint, authenticated by an HMAC-SHA256 binding.
They do not grant authority and cannot represent a witnessed result.

## Provides

- `ContentRef` (trusted): digest, source capability, origin metadata, retention policy, taint class, HMAC-SHA256 binding. Serialize only (no deserializer).
- `UntrustedContentRef`: wire container requiring authentication via `ContentResolver.resolve` (validates digest format `sha256:` + 64 hex, binding 64 hex, bounded metadata text, and capture frame requirements).
- `ContentAuthority`: root key container (32-byte secret) minting narrow single-purpose handles:
  - `ContentIssuer`: mints `ContentRef` for a fixed source capability.
  - `ContentResolver`: authenticates a `ContentRef` without issuance or retention modification capability.
- `CaptureFrame`, `OriginMetadata` and the wire enums `SourceCapability`, `OriginKind`, `TaintClass`, `RetentionPolicy`, `ReceiptRung`.
- Two typed error families: `ContractError` and `AuthorityError`.

## Validation boundaries

Capture dimensions are positive integers from 1 through 8192 inclusive; booleans
and floating-point dimensions are refused with `EmptyViewport`, and oversized
integers with `ViewportTooLarge`. DPR accepts finite integers or floats in
`[1, 3]`, excluding booleans, and refuses invalid values with
`InvalidDevicePixelRatio`.

Origin metadata requires a real capture frame for browser captures and allowed
root files, including direct construction. Wire policy fields must identify
declared enum members. Bounded text must be valid UTF-8 and retain its original
typed refusal for invalid text. Authority secrets accept 32-byte `bytes`,
`bytearray`, or lists of integer byte values; booleans are not byte values.

The development suite includes Hypothesis properties for authenticated wire
roundtrips and foreign-key and metadata tampering. Hypothesis is a development
dependency only.

## API absence

1. Issue without retention policy or taint class: `issue()` requires positional parameters; `mypy --strict` rejects omitted args.
2. Resolver issuance escape: `ContentResolver` exposes only `resolve()`; `issue()` is absent (`AttributeError`).
3. Resolver retention transition: `ContentResolver` cannot modify retention; `tighten()` is absent (`AttributeError`).

## The Float Law (F5)

The only float inside the HMAC-SHA256 byte domain is Device Pixel Ratio (`DPR`) ∈ `[1.0, 3.0]`, written in plain decimal by `json.dumps()`.

## Ceilings & Does Not Provide

- **Authority Granting**: References carry policy metadata and cryptographic binding; they do not grant permissions or execute actions.
- **In-memory Secret Zeroization**: CPython cannot guarantee secret zeroization (GC and `hmac` copy key buffers). Best-effort buffer wiping is provided on `.close()`.
- **In-process tamper resistance**: Python attributes remain writable; this is not an in-process security boundary against code that can modify private attributes.
