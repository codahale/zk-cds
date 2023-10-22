use std::collections::HashMap;

use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::ops::ReduceNonZero;
use p256::elliptic_curve::sec1::{self, FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::Field;
use p256::{AffinePoint, EncodedPoint, NistP256, Scalar};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// A server in a hypothetical CDS.
#[derive(Debug)]
pub struct Server {
    secret: Scalar,
    users: HashMap<[u8; 8], HashMap<EncodedPoint, EncodedPoint>>,
}

impl Server {
    /// Create a new server with a random secret and the given address book of phone numbers and
    /// user IDs.
    pub fn new(rng: impl CryptoRng + RngCore, users: &HashMap<&str, Uuid>) -> Server {
        // Generate a random secret.
        let secret = Scalar::random(rng);

        // Blind the address book.
        let mut blinded = HashMap::with_capacity(users.len());
        for (phone_number, user_id) in users {
            // Hash the phone number and truncate it to 8 bytes.
            let hash: [u8; 32] = sha2::Sha256::new()
                .chain_update(phone_number.as_bytes())
                .finalize()
                .into();
            let prefix: [u8; 8] = hash[..8].try_into().expect("should be 8 bytes");

            // Hash the phone number to a point on the curve and blind it with the server secret.
            let phone_number = NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
                &[phone_number.as_bytes()],
                &[b"stupid-psi-tricks"],
            )
            .expect("")
                * secret;

            // Encode the user ID as a point and blind it with both the server's secret and the hash of
            // the phone number.
            let user_id =
                encode_to_point(user_id) * secret * Scalar::reduce_nonzero_bytes(&hash.into());

            // Record the (prefix, phone_number, user_id) row.
            blinded.entry(prefix).or_insert(HashMap::new()).insert(
                phone_number.to_affine().to_encoded_point(true),
                user_id.to_affine().to_encoded_point(true),
            );
        }

        Server {
            secret,
            users: blinded,
        }
    }

    /// Given a hash prefix and a blinded phone number point, return the double-blinded phone number
    /// point and the bucket of users.
    pub fn find_bucket(
        &self,
        (prefix, phone_number): ([u8; 8], EncodedPoint),
    ) -> (EncodedPoint, HashMap<EncodedPoint, EncodedPoint>) {
        // Double-blind the given point.
        let phone_number = AffinePoint::from_encoded_point(&phone_number).unwrap() * self.secret;

        // Return the double-blinded point and sets.
        (
            phone_number.to_encoded_point(true),
            self.users.get(&prefix).cloned().unwrap_or_default(),
        )
    }

    /// Given a blinded user ID point, unblind it and recover the encoded UUID.
    pub fn unblind_user_id(&self, blinded_user_id: &EncodedPoint) -> Option<Uuid> {
        // Unblind the double blinded point, giving us the server's point for this phone number.
        let user_id = (AffinePoint::from_encoded_point(blinded_user_id).unwrap()
            * self.secret.invert().unwrap())
        .to_encoded_point(true);
        Uuid::from_slice(&user_id.as_bytes()[1..17]).ok()
    }
}

/// A client in a hypothetical CDS.
#[derive(Debug)]
pub struct Client {
    secret: Scalar,
}

impl Client {
    pub fn new(rng: impl CryptoRng + RngCore) -> Client {
        Client {
            secret: Scalar::random(rng),
        }
    }
    /// Initiate a client request for the given phone number. Returns the hash prefix of the phone
    /// number and a blinded phone number point.
    pub fn request_phone_number(&self, phone_number: &str) -> ([u8; 8], EncodedPoint) {
        // Hash the phone number and truncate it to 8 bytes.
        let hash: [u8; 32] = sha2::Sha256::new()
            .chain_update(phone_number.as_bytes())
            .finalize()
            .into();
        let prefix: [u8; 8] = hash[..8].try_into().expect("should be 8 bytes");

        // Hash the phone number to a point on the curve and blind it with the client secret.
        let phone_number = NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
            &[phone_number.as_bytes()],
            &[b"stupid-psi-tricks"],
        )
        .expect("")
            * self.secret;

        (prefix, phone_number.to_affine().to_encoded_point(true))
    }

    /// Given a double-blinded phone number point and bucket of users from the server, unblind the
    /// double-blinded point, look for the double-blinded user ID point, and return the unblinded
    /// user ID point, if any can be found.
    pub fn process_bucket(
        &self,
        (double_blinded_phone_number, users): (EncodedPoint, HashMap<EncodedPoint, EncodedPoint>),
        phone_number: &str,
    ) -> Option<EncodedPoint> {
        // Unblind the double blinded point, giving us the server's point for this phone number.
        let blinded_point = (AffinePoint::from_encoded_point(&double_blinded_phone_number)
            .unwrap()
            * self.secret.invert().unwrap())
        .to_encoded_point(true);

        // Use it to find the user ID point, if any.
        if let Some(user_id) = users.get(&blinded_point).cloned() {
            // Hash the phone number and reduce it to a scalar.
            let hash: [u8; 32] = sha2::Sha256::new()
                .chain_update(phone_number.as_bytes())
                .finalize()
                .into();
            let phone_number = Scalar::reduce_nonzero_bytes(&hash.into());

            // Unblind the user ID point.
            let user_id =
                AffinePoint::from_encoded_point(&user_id).unwrap() * phone_number.invert().unwrap();

            // Return it.
            Some(user_id.to_affine().to_encoded_point(true))
        } else {
            None
        }
    }
}

/// Use a try-and-increment algorithm to encode the given user ID as a point on the P-256 curve.
///
/// **N.B.:** This is a variable time encoding, but it isn't used online.
fn encode_to_point(user_id: &Uuid) -> AffinePoint {
    let mut buf = [0u8; 33];
    buf[0] = sec1::Tag::Compact.into();
    buf[1..17].copy_from_slice(user_id.as_bytes());

    let mut i = 0u128;
    loop {
        buf[17..].copy_from_slice(&i.to_le_bytes());
        if let Ok(encoded) = EncodedPoint::from_bytes(buf) {
            if let Some(p) = AffinePoint::from_encoded_point(&encoded).into() {
                return p;
            }
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn round_trip() {
        // Start with a map of phone numbers to user IDs.
        let mut users = HashMap::<&str, Uuid>::new();
        users.insert("123-456-7890", Uuid::new_v4());
        users.insert("123-8675309", Uuid::new_v4());

        // Initialize a server.
        let server = Server::new(OsRng, &users);

        // Initialize a client.
        let client = Client::new(OsRng);

        // Generate a blinded client request.
        let req = client.request_phone_number("123-456-7890");

        // Map the blinded request to a map of phone number points to user ID points.
        let resp = server.find_bucket(req);

        // Look through the bucket for the phone number and get the blinded user ID.
        let blinded_user_id = client
            .process_bucket(resp, "123-456-7890")
            .expect("should be a valid phone number");

        // Send the blinded user ID to the server, which unblinds it.
        let user_id = server.unblind_user_id(&blinded_user_id);

        assert_eq!(user_id, users.get("123-456-7890").cloned());
    }
}
