use thiserror::Error;

/// Possible errors thrown by methods implemented for Identity and it's public counterpart.
#[derive(Error, Debug)]
pub enum Error {
	/// Invalid hash salt provided
	#[error("Invalid hash salt provided")]
	InvalidHashSalt,

	/// Invalid username
	#[error("Invalid username")]
	InvalidUsername,

	/// Invalid hash data
	#[error("Invalid hash data")]
	InvalidHashData,

	/// Invalid username, password or salt
	#[error("Invalid username, password or salt")]
	InvalidArguments,

	/// Invalid  derived key
	#[error("Invalid  derived key")]
	InvalidDerivedKey,

	/// Unknown signature error
	#[error("Unknown signature error")]
	SignatureError,

	/// Invalid private key
	#[error("Invalid private key")]
	InvalidPrivateKey,

	/// Invalid public key
	#[error("Invalid public key")]
	InvalidPublicKey,

	/// Invalid signature
	#[error("Invalid signature")]
	InvalidSignature,

	/// Base 64 string decoding error
	#[error("Base 64 string decoding error")]
	InvalidBase64String,

	/// String is empty
	#[error("String is empty")]
	EmptyString,

	/// Version is unknown and invalid
	#[error("Version is unknown and invalid")]
	InvalidUnknownVersion,
}
