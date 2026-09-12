# Bounded comparison model (builtin library 0x00010001)

`memcmp` now models the sign of the first differing unsigned byte over at most
256 bytes. Pointers and length must be concrete. Byte values may be symbolic;
memory taint propagates to the result. The nonzero return magnitude remains
symbolic rather than being incorrectly fixed to -1 or 1. Unsupported signatures
and symbolic pointers retain unknown-call handling. Missing memory is not equality.

`strlen` requires a concrete NUL within 256 bytes. A symbolic byte, failed read or
exhausted bound no longer becomes a concrete length from a sampled solver model.

The builtin model-library identifier changes from 0x00010000 to 0x00010001 so
saved builtin environments cannot silently load under changed semantics.
`xair_sym_environment_create_builtin` exposes the existing versioned model
environment without constructing a process; callers provide memory/register seeds.

Tests cover memcmp equality and signed-result constraints, core symbolic behavior,
environment internals and snapshot validation. The affected tests passed on both
Windows and Linux through IndagoRev's linked test targets (each capped at 90s).
