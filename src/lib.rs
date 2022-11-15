#![warn(missing_docs)]
//! # Zemi Identity
//! 
//! Identity tools that can be used to create credentials without a trusted third party.
//! This library can deterministically produce an asymmetric keypair from user credentials.
//! It also generates a consistent public identity tied to the provided username that cannot easily be used to discover the username.
//! ### Important Exports
//! * [Identity](Identity)
//! * [PublicIdentity](PublicIdentity)
//! ### Version 1 (current)
//! * Uses [Argon2di](argon2) to derive key material.
//! * Uses [ed25519](ed25519_dalek) elliptical curve cryptography for keys. 
//! 
//! ### Example: From Credentials
//! ```
//! # use zemi_identity::*;
//! let identity = Identity::from_credentials("username", "password", "salt", Version::V1)?;
//! let signature = identity.sign(b"message")?;
//! let verify_op = identity.verify(b"message", &signature);
//! assert!(verify_op.is_ok());
//! # Ok::<(), Error>(())
//! ```
//! 
//! ### Example: To Public Identity
//! ```
//! # use zemi_identity::*;
//! let identity = Identity::from_credentials("username", "password", "salt", Version::V1)?;
//! # let signature = identity.sign(b"message")?;
//! let public = identity.to_public_identity();
//! let verify_op = public.verify(b"message", &signature);
//! assert!(verify_op.is_ok());
//! # Ok::<(), Error>(())
//! ```


pub use ed25519_dalek::{Keypair, Signer, Verifier, SecretKey, PublicKey, Signature};
use base64_url;
use std::str;

mod error;
pub use error::Error;

mod utils;
use utils::argon2di_u8;

#[cfg(test)]
mod tests;




/// An identity that includes public and private key components. 
/// This can be used to both sign and verify.
pub struct Identity {
	/// The algorithm version for this Identity.
	pub version: Version,

	/// The public identity derived from the username. This can be freely distributed ✓.
	pub public_id: String,

	/// The public and private keys for this Identity. This should **not** be shared 𐄂.
	pub keypair: Keypair,
}

/// Identity that includes only public components. 
/// This can be used to verify, but not sign.
pub struct PublicIdentity {
	/// The algorithm version for this PublicIdentity.
	pub version: Version,

	/// The public identity derived from the username. This can be freely distributed ✓.
	pub public_id: String,

	/// The public key for this PublicIdentity. This can be freely distributed ✓.
	pub public_key: PublicKey,
}

/// The version of the derivation algorithm that turns credentials into keys.
#[derive(Copy, Clone, PartialEq)]
pub enum Version {
	/// The first version of the derivation algorithm.
	/// EdDSA + Argon2di.
	V1 = 1,

	/// Catch-all version.
	Unknown,
}

impl Version {
	/// Converts the Version to a u8.
	fn to_u8(&self) -> u8 {
		match self {
			Version::V1 => 1u8,
			Version::Unknown => 0u8,
		}
	}

	/// Converts a u8 to a Version.
	fn from_u8(version: &u8) -> Version {
		match version {
			1 => Version::V1,
			_ => Version::Unknown,
		}
	}
}

impl Identity {
	/// Converts credentials into an Identity. An Identity includes public and private key, a public id, and a version.
	/// ```
	/// # use zemi_identity::*;
	/// let identity = Identity::from_credentials("username", "password", "salt", Version::V1)?;
	/// # Ok::<(), Error>(())
	/// ```
	pub fn from_credentials(username: &str, password: &str, salt: &str, version: Version) -> Result<Identity, Error> {
		let user_hash = match argon2di_u8(username, salt) {
			Ok(hash) => hash,
			Err(_) => return Err(Error::InvalidArguments),
		};

		let mash = format!("{username}{password}");
		let mash_str = mash.as_str();
		let derived_key = match argon2di_u8(mash_str, salt) {
			Ok(hash) => hash,
			Err(_) => return Err(Error::InvalidArguments),
		};

		let public_id: String = base64_url::encode(&user_hash);
	
		let mut private_key: [u8; 32] = Default::default();
		private_key.copy_from_slice(&derived_key[..32]);

		let secret = match SecretKey::from_bytes(&private_key) {
			Ok(secret) => secret,
			Err(_) => return Err(Error::InvalidDerivedKey),
		};

		let public = PublicKey::from(&secret);
		let keypair = Keypair { secret, public };

		Ok(Identity { version, public_id, keypair })
	}

	/// ```
	/// # use zemi_identity::*;
	/// let identity = Identity::from_credentials("username", "password", "salt", Version::V1)?;
	/// let signature = identity.sign(b"message")?;
	/// # Ok::<(), Error>(())
	/// ```
	/// Signs a message using the private key.
	pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
		let signature: Signature = match self.keypair.try_sign(message) {
			Ok(signature) => signature,
			Err(_) => return Err(Error::SignatureError),
		};
		Ok(signature)
	}

	/// ```
	/// # use zemi_identity::*;
	/// let identity = Identity::from_credentials("username", "password", "salt", Version::V1)?;
	/// let signature = identity.sign(b"message")?;
	/// let verify_op = identity.verify(b"message", &signature);
	/// assert!(verify_op.is_ok());
	/// # Ok::<(), Error>(())
	/// ```
	/// Verifies a message using the public key. 
	/// This method can also be called from a [PublicIdentity](PublicIdentity).
	pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
		match self.keypair.verify(message, signature) {
			Ok(_) => Ok(()),
			Err(_) => Err(Error::InvalidSignature),
		}
	}

	/// Serializes the struct to a single url-safe base64 string.
	/// ```
	/// # use zemi_identity::*;
	/// let identity = Identity::from_credentials("username", "password", "salt", Version::V1)?;
	/// let url_safe_b64 = identity.to_b64url()?;	// -> AWlfU1LH4wkBHJpmu...
	/// # Ok::<(), Error>(())
	/// ```
	pub fn to_b64url(&self) -> Result<String, Error> {
		let public_id = match base64_url::decode(&self.public_id) {
			Ok(id) => id,
			Err(_) => return Err(Error::InvalidBase64String),
		};

		let merged: Vec<u8> = [
			&[self.version.to_u8()],			// 1 bytes
			&public_id as &[u8],				// 64 bytes
			self.keypair.public.as_bytes(),		// 32 bytes
			self.keypair.secret.as_bytes(),		// 32 bytes
		].concat();

		Ok(base64_url::encode(&merged))
	}

	/// Deserializes a url-safe base64 string.
	/// ```
	/// # use zemi_identity::*;
	/// let identity = Identity::from_credentials("username", "password", "salt", Version::V1)?;
	/// let url_safe_b64 = identity.to_b64url()?;	// -> AWlfU1LH4wkBHJpmu...
	/// let deserialized = Identity::from_b64url(&url_safe_b64)?; // -> a copy of "identity" 
	/// # Ok::<(), Error>(())
	/// ```
	pub fn from_b64url(b64_id: &str) -> Result<Identity, Error> {
		let decoded = match base64_url::decode(b64_id) {
			Ok(id) => id,
			Err(_) => return Err(Error::InvalidBase64String),
		};

		if b64_id.is_empty() { return Err(Error::EmptyString); }

		let version_u8 = decoded[0];
		let version = Version::from_u8(&version_u8);
		
		match version {
			Version::V1 => {
				if decoded.len() != 129 { return Err(Error::InvalidBase64String); }

				let public_id = base64_url::encode(&decoded[1..65] as &[u8]);
				let public = match PublicKey::from_bytes(&decoded[65..97] as &[u8]) {
					Ok(key) => key,
					Err(_) => return Err(Error::InvalidBase64String),
				};
				let secret = match SecretKey::from_bytes(&decoded[97..129] as &[u8]) {
					Ok(key) => key,
					Err(_) => return Err(Error::InvalidBase64String),
				};
				let keypair = Keypair { public, secret };
				Ok(Identity { version, public_id, keypair })
			},
			Version::Unknown => Err(Error::InvalidUnknownVersion),
		}
	}

	/// Converts the Identity into a publicly distributable form.
	pub fn to_public_identity(&self) -> PublicIdentity {
		PublicIdentity {
			version: self.version,
			public_id: self.public_id.clone(),
			public_key: self.keypair.public,
		}
	}

}

impl PublicIdentity {
	/// Converts credentials into a PublicIdentity. A PublicIdentity has only public components that can safely be distributed.
	/// ```
	/// # use zemi_identity::*;
	/// let identity = PublicIdentity::from_credentials("username", "password", "salt", Version::V1)?;
	/// # Ok::<(), Error>(())
	/// ```
	pub fn from_credentials(username: &str, password: &str, salt: &str, version: Version) -> Result<PublicIdentity, Error> {
		let identity = Identity::from_credentials(username, password, salt, version)?;
		Ok(identity.to_public_identity())
	}

	/// Serializes the struct to a single url-safe base64 string.
	/// ```
	/// # use zemi_identity::*;
	/// let identity = PublicIdentity::from_credentials("username", "password", "salt", Version::V1)?;
	/// let url_safe_b64 = identity.to_b64url()?;	// -> AWlfU1LH4wkBHJpmu...
	/// # Ok::<(), Error>(())
	/// ```
	pub fn to_b64url(&self) -> Result<String, Error> {
		let public_id = match base64_url::decode(&self.public_id) {
			Ok(id) => id,
			Err(_) => return Err(Error::InvalidBase64String),
		};

		let merged: Vec<u8> = [
			&[self.version.to_u8()],			// 1 bytes
			&public_id as &[u8],				// 64 bytes
			self.public_key.as_bytes(),			// 32 bytes
		].concat();

		Ok(base64_url::encode(&merged))
	}

	/// Deserializes a url-safe base64 string.
	/// ```
	/// # use zemi_identity::*;
	/// let identity = PublicIdentity::from_credentials("username", "password", "salt", Version::V1)?;
	/// let url_safe_b64 = identity.to_b64url()?;	// -> AWlfU1LH4wkBHJpmu...
	/// let deserialized = PublicIdentity::from_b64url(&url_safe_b64)?; // -> a copy of "identity" 
	/// # Ok::<(), Error>(())
	/// ```
	pub fn from_b64url(b64_id: &str) -> Result<PublicIdentity, Error> {
		let decoded = match base64_url::decode(b64_id) {
			Ok(id) => id,
			Err(_) => return Err(Error::InvalidBase64String),
		};

		if b64_id.is_empty() { return Err(Error::EmptyString); }

		let version_u8 = decoded[0];
		let version = Version::from_u8(&version_u8);

		match version {
			Version::V1 => {
				if decoded.len() < 97 { return Err(Error::InvalidBase64String); }

				let public_id = base64_url::encode(&decoded[1..65] as &[u8]);
				let public_key = match PublicKey::from_bytes(&decoded[65..97] as &[u8]) {
					Ok(key) => key,
					Err(_) => return Err(Error::InvalidBase64String),
				};
				Ok(PublicIdentity { version, public_id, public_key })
			},
			Version::Unknown => Err(Error::InvalidUnknownVersion),
		}
	}

	/// Verifies the validity of a message signature.
	/// 
	pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
		match self.public_key.verify(message, signature) {
			Ok(_) => Ok(()),
			Err(_) => Err(Error::InvalidSignature),
		}
	}
}


