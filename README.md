# zemi-identity

## Zemi Identity

Identity tools that can be used to create credentials without a trusted third party.
This library can deterministically produce an asymmetric keypair from user credentials.
It also generates a consistent public identity tied to the provided username that cannot easily be used to discover the username.
#### Important Exports
* [Identity](Identity)
* [PublicIdentity](PublicIdentity)
#### Version 1 (current)
* Uses [Argon2di](argon2) to derive key material.
* Uses [ed25519](ed25519_dalek) elliptical curve cryptography for keys.

#### Example: From Credentials
```rust
let identity = Identity::from_credentials("username", "password", "salt", Version::V1)?;
let signature = identity.sign(b"message")?;
let verify_op = identity.verify(b"message", &signature);
assert!(verify_op.is_ok());
```

#### Example: To Public Identity
```rust
let identity = Identity::from_credentials("username", "password", "salt", Version::V1)?;
let public = identity.to_public_identity();
let verify_op = public.verify(b"message", &signature);
assert!(verify_op.is_ok());
```
