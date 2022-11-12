use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
	#[error("Invalid hash salt provided")]
	InvalidHashSalt,

	#[error("Invalid username")]
	InvalidUsername,

	#[error("Invalid hash data")]
	InvalidHashData,

	#[error("Invalid username, password or salt")]
	InvalidArguments,

	#[error("Invalid  derived key")]
	InvalidDerivedKey,

	#[error("Unknown signature error")]
	SignatureError,

	#[error("Invalid private key")]
	InvalidPrivateKey,

	#[error("Invalid public key")]
	InvalidPublicKey,

	#[error("Invalid signature")]
	InvalidSignature,

	#[error("Base 64 string decoding error")]
	InvalidBase64String,

	#[error("String is empty")]
	EmptyString,

	#[error("Version is unknown and invalid")]
	InvalidUnknownVersion,
}
