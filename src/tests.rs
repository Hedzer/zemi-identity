
pub use crate::{Keypair, SecretKey};
use crate::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_from_credentials_v1() {
		let id = Identity::from_credentials("username", "password", "salt", Version::V1);
        assert!(id.is_ok());
    }

	#[test]
    fn zero_size_strings_work_v1() {
		let id = Identity::from_credentials("", "", "", Version::V1);
        assert!(id.is_ok());
    }

	#[test]
	fn can_sign_and_verify_v1() {
		let id = Identity::from_credentials("username", "password", "salt", Version::V1).unwrap();
		let signature_op = id.sign(b"test");
		assert!(signature_op.is_ok());
		
		let signature = signature_op.unwrap();
		let verify_op = id.verify(b"test", &signature);
		assert!(verify_op.is_ok());
	}

	#[test]
	fn private_can_sign_and_public_can_verify_v1() {
		let id = Identity::from_credentials("username", "password", "salt", Version::V1).unwrap();
		let signature_op = id.sign(b"test");
		assert!(signature_op.is_ok());
		
		let signature = signature_op.unwrap();
		let verify_op = id.to_public_identity().verify(b"test", &signature);
		assert!(verify_op.is_ok());
	}

	#[test]
	fn can_b64_serde_v1() {
		let id = Identity::from_credentials("username", "password", "salt", Version::V1).unwrap();
		let signature_op = id.sign(b"test");
		assert!(signature_op.is_ok());

		let b64_id = id.to_b64url().unwrap();
		println!("{}", b64_id);
		let restored_id_op = Identity::from_b64url(&b64_id);
		assert_eq!(restored_id_op.is_ok(), true);

		let restored_id = restored_id_op.unwrap();
		let verify_op = restored_id.verify(b"test", &signature_op.unwrap());
		assert!(verify_op.is_ok());
		assert_eq!(restored_id.to_b64url().unwrap(), id.to_b64url().unwrap());
	}

	#[test]
	fn private_cant_parse_public_b64() {
		let id = Identity::from_credentials("username", "password", "salt", Version::V1).unwrap();
		let public_id = id.to_public_identity();
		let public_b64 = public_id.to_b64url().unwrap();

		assert_ne!(public_id.to_b64url().unwrap(), id.to_b64url().unwrap());
		assert!(Identity::from_b64url(&public_b64).is_err());
	}

	#[test]
	fn public_serde_works() {
		let id = PublicIdentity::from_credentials("username", "password", "salt", Version::V1).unwrap();
		let b64_id = id.to_b64url().unwrap();
		println!("{}", b64_id);
		assert!(PublicIdentity::from_b64url(&b64_id).is_ok());
	}
}
