# zemi-identity

## Zemi Identity

Identity tools that can be used to create credentials without a trusted third party.
This library can deterministically produce an asymmetric keypair from user credentials.
It also generates a consistent public identity tied to the provided username that cannot easily be used to discover the username.
#### Important Exports
* [Identity](https://docs.rs/zemi-identity/0.1.1/zemi_identity/struct.Identity.html)
* [PublicIdentity](https://docs.rs/zemi-identity/0.1.1/zemi_identity/struct.PublicIdentity.html)
#### Version 1 (current)
* Uses [Argon2di](https://docs.rs/rust-argon2/1.0.0/argon2/index.html) to derive key material.
* Uses [ed25519](https://docs.rs/ed25519-dalek/1.0.1/ed25519_dalek/index.html) elliptical curve cryptography for keys.

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

More detailed docs can be found at [https://docs.rs/zemi-identity/](https://docs.rs/zemi-identity/)