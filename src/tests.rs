
pub use crate::{Keypair, SecretKey};
use crate::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_create_from_credentials_v1() {
		let id = Identity::from_credentials("username", "password", "salt", Version::V1);
        assert_eq!(id.is_ok(), true);
    }

	#[test]
    fn zero_size_strings_work_v1() {
		let id = Identity::from_credentials("", "", "", Version::V1);
        assert_eq!(id.is_ok(), true);
    }

	#[test]
	fn can_sign_and_verify_v1() {
		let id = Identity::from_credentials("username", "password", "salt", Version::V1).unwrap();
		let signature_op = id.sign(b"test");
		assert_eq!(signature_op.is_ok(), true);
		
		let signature = signature_op.unwrap();
		let verify_op = id.verify(b"test", &signature);
		assert_eq!(verify_op.is_ok(), true);
	}

	#[test]
	fn can_b64_serde_v1() {
		let id = Identity::from_credentials("username", "password", "salt", Version::V1).unwrap();
		let signature_op = id.sign(b"test");
		assert_eq!(signature_op.is_ok(), true);

		let b64_id = id.to_b64url().unwrap();
		let restored_id_op = Identity::from_b64url(&b64_id);
		assert_eq!(restored_id_op.is_ok(), true);

		let restored_id = restored_id_op.unwrap();
		let verify_op = restored_id.verify(b"test", &signature_op.unwrap());
		assert_eq!(verify_op.is_ok(), true);
	}
}
