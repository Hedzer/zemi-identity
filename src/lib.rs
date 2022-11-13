
pub use ed25519_dalek::{Keypair, Signer, Verifier, SecretKey, PublicKey, Signature};
use base64_url::base64;
use std::str;

mod error;
pub use error::Error;

mod utils;
use utils::argon2id_u8;

#[cfg(test)]
mod tests;

pub struct Identity {
	version: Version,
	public_id: String,
	keypair: Keypair,
}

pub struct PublicIdentity {
	version: Version,
	public_id: String,
	public_key: PublicKey,
}

#[derive(Copy, Clone, PartialEq)]
pub enum Version {
	V1 = 1,
	Unknown,
}

impl Version {
	fn to_u8(&self) -> u8 {
		match self {
			Version::V1 => 1u8,
			Version::Unknown => 0u8,
		}
	}

	fn from_u8(version: &u8) -> Version {
		match version {
			1 => Version::V1,
			_ => Version::Unknown,
		}
	}
}

impl Identity {
	pub fn from_credentials(username: &str, password: &str, salt: &str, version: Version) -> Result<Identity, Error> {
		let user_hash = match argon2id_u8(username, salt) {
			Ok(hash) => hash,
			Err(_) => return Err(Error::InvalidArguments),
		};

		let mash = format!("{username}{password}");
		let mash_str = mash.as_str();
		let derived_key = match argon2id_u8(mash_str, salt) {
			Ok(hash) => hash,
			Err(_) => return Err(Error::InvalidArguments),
		};

		let public_id: String = base64::encode(&user_hash);
	
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

	pub fn sign(&self, message: &[u8]) -> Result<Signature, Error> {
		let signature: Signature = match self.keypair.try_sign(message) {
			Ok(signature) => signature,
			Err(_) => return Err(Error::SignatureError),
		};
		Ok(signature)
	}

	pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
		match self.keypair.verify(message, signature) {
			Ok(_) => Ok(()),
			Err(_) => Err(Error::InvalidSignature),
		}
	}

	pub fn to_b64url(&self) -> Result<String, Error> {
		let public_id = match base64::decode(&self.public_id) {
			Ok(id) => id,
			Err(_) => return Err(Error::InvalidBase64String),
		};

		let merged: Vec<u8> = [
			&[self.version.to_u8()],			// 1 bytes
			&public_id as &[u8],				// 64 bytes
			self.keypair.public.as_bytes(),		// 32 bytes
			self.keypair.secret.as_bytes(),		// 32 bytes
		].concat();

		Ok(base64::encode(merged))
	}

	pub fn from_b64url(b64_id: &str) -> Result<Identity, Error> {
		let decoded = match base64::decode(b64_id) {
			Ok(id) => id,
			Err(_) => return Err(Error::InvalidBase64String),
		};

		if b64_id.is_empty() { return Err(Error::EmptyString); }

		let version_u8 = decoded[0];
		let version = Version::from_u8(&version_u8);
		
		match version {
			Version::V1 => {
				if decoded.len() != 129 { return Err(Error::InvalidBase64String); }

				let public_id = base64::encode(&decoded[1..65] as &[u8]);
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

	pub fn to_public_identity(&self) -> PublicIdentity {
		PublicIdentity {
			version: self.version,
			public_id: self.public_id.clone(),
			public_key: self.keypair.public,
		}
	}

}

impl PublicIdentity {
	pub fn from_credentials(username: &str, password: &str, salt: &str, version: Version) -> Result<PublicIdentity, Error> {
		let identity = Identity::from_credentials(username, password, salt, version)?;
		Ok(identity.to_public_identity())
	}

	pub fn to_string(&self) -> String {
		let version = base64::encode([self.version.to_u8()]);
		let public_id = self.public_id.clone();
		let public_key = base64::encode(self.public_key);
		return format!("{version}.{public_id}.{public_key}");
	}

	pub fn to_b64url(&self) -> Result<String, Error> {
		let public_id = match base64::decode(&self.public_id) {
			Ok(id) => id,
			Err(_) => return Err(Error::InvalidBase64String),
		};

		let merged: Vec<u8> = [
			&[self.version.to_u8()],			// 1 bytes
			&public_id as &[u8],				// 64 bytes
			self.public_key.as_bytes(),			// 32 bytes
		].concat();

		Ok(base64::encode(merged))
	}

	pub fn from_b64url(b64_id: &str) -> Result<PublicIdentity, Error> {
		let decoded = match base64::decode(b64_id) {
			Ok(id) => id,
			Err(_) => return Err(Error::InvalidBase64String),
		};

		if b64_id.is_empty() { return Err(Error::EmptyString); }

		let version_u8 = decoded[0];
		let version = Version::from_u8(&version_u8);

		match version {
			Version::V1 => {
				if decoded.len() >= 97 { return Err(Error::InvalidBase64String); }

				let public_id = base64::encode(&decoded[1..65] as &[u8]);
				let public_key = match PublicKey::from_bytes(&decoded[65..97] as &[u8]) {
					Ok(key) => key,
					Err(_) => return Err(Error::InvalidBase64String),
				};
				Ok(PublicIdentity { version, public_id, public_key })
			},
			Version::Unknown => Err(Error::InvalidUnknownVersion),
		}
	}

	pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
		match self.public_key.verify(message, signature) {
			Ok(_) => Ok(()),
			Err(_) => Err(Error::InvalidSignature),
		}
	}
}


