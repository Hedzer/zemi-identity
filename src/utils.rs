use argon2::{self, Config};
use sha2::{Sha512, Digest};
use crate::Error;

pub fn argon_u8(data: &str, salt: &str) -> Result<[u8; 64], Error> {
	let config = Config::default();
	let fixed_salt = sha512_u8(salt);
	let hash = argon2::hash_encoded(data.as_bytes(), &fixed_salt, &config).unwrap();
	let result = sha512_u8(hash.as_str());
	return Ok(result);
}

pub fn sha512_u8(data: &str) -> [u8; 64] {
	let mut hasher = Sha512::new();
	hasher.update(data.as_bytes());
	let finalized = hasher.finalize();
	let finalized_u8 = &finalized[..64];

	let mut result: [u8; 64] = [0; 64];
	result.copy_from_slice(finalized_u8);
	return result;
}
