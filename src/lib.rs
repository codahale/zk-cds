use std::collections::HashMap;

use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::ops::ReduceNonZero;
use p256::elliptic_curve::sec1::{self, FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::Field;
use p256::{AffinePoint, EncodedPoint, NistP256, ProjectivePoint, Scalar};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// A server in a hypothetical CDS.
#[derive(Debug)]
pub struct Server {
    d_s: Scalar,
    buckets: HashMap<[u8; 8], HashMap<EncodedPoint, EncodedPoint>>,
}

impl Server {
    /// Create a new server with a random secret and the given address book of phone numbers and
    /// user IDs.
    pub fn new(rng: impl CryptoRng + RngCore, users: &HashMap<&str, Uuid>) -> Server {
        // Generate a random secret.
        let d_s = Scalar::random(rng);

        // Blind the address book and group it into buckets by hash prefix.
        let mut buckets = HashMap::new();
        for (p, u) in users {
            // Hash the phone number and truncate it to 8 bytes.
            let h = sha256(p.as_bytes());
            let prefix: [u8; 8] = h[..8].try_into().expect("should be 8 bytes");

            // Hash the phone number to a point on the curve and blind it with the server secret.
            let s_p = hash_to_curve(p.as_bytes()) * d_s;

            // Encode the user ID as a point and blind it with both the server's secret and the hash
            // of the phone number.
            let s_u = encode_to_point(u) * d_s * Scalar::reduce_nonzero_bytes(&h.into());

            // Record the (prefix, phone_number, user_id) row.
            buckets.entry(prefix).or_insert(HashMap::new()).insert(
                s_p.to_affine().to_encoded_point(true),
                s_u.to_affine().to_encoded_point(true),
            );
        }

        Server { d_s, buckets }
    }

    /// Given a hash prefix and a blinded phone number point, return the double-blinded phone number
    /// point and the bucket of users.
    pub fn find_bucket(
        &self,
        (prefix, c_p): ([u8; 8], EncodedPoint),
    ) -> (EncodedPoint, HashMap<EncodedPoint, EncodedPoint>) {
        // Decode the point and double-blind it.
        let c_p = AffinePoint::from_encoded_point(&c_p).expect("should be a valid point");
        let sc_p = c_p * self.d_s;

        // Find the bucket of blinded phone number and user ID points.
        let bucket = self.buckets.get(&prefix).cloned().unwrap_or_default();

        // Return the double-blinded point and sets.
        (sc_p.to_encoded_point(true), bucket)
    }

    /// Given a blinded user ID point, unblind it and recover the encoded UUID.
    pub fn unblind_user_id(&self, s_u: &EncodedPoint) -> Option<Uuid> {
        // Unblind the double blinded point, giving us the server's point for this phone number.
        let s_u = AffinePoint::from_encoded_point(s_u).expect("should be a valid point");
        let u = (s_u * self.d_s.invert().expect("should be invertible")).to_encoded_point(true);
        Uuid::from_slice(&u.as_bytes()[1..17]).ok()
    }
}

/// A client in a hypothetical CDS.
#[derive(Debug)]
pub struct Client {
    d_c: Scalar,
}

impl Client {
    pub fn new(rng: impl CryptoRng + RngCore) -> Client {
        Client {
            d_c: Scalar::random(rng),
        }
    }
    /// Initiate a client request for the given phone number. Returns the hash prefix of the phone
    /// number and a blinded phone number point.
    pub fn request_phone_number(&self, p: &str) -> ([u8; 8], EncodedPoint) {
        // Hash the phone number and truncate it to 8 bytes.
        let h = sha256(p.as_bytes());
        let prefix: [u8; 8] = h[..8].try_into().expect("should be 8 bytes");

        // Hash the phone number to a point on the curve and blind it with the client secret.
        let c_p = hash_to_curve(p.as_bytes()) * self.d_c;

        (prefix, c_p.to_affine().to_encoded_point(true))
    }

    /// Given a double-blinded phone number point and bucket of users from the server, unblind the
    /// double-blinded point, look for the double-blinded user ID point, and return the unblinded
    /// user ID point, if any can be found.
    pub fn process_bucket(
        &self,
        (sc_p, bucket): (EncodedPoint, HashMap<EncodedPoint, EncodedPoint>),
        p: &str,
    ) -> Option<EncodedPoint> {
        // Unblind the double blinded point, giving us the server's point for this phone number.
        let sc_p = AffinePoint::from_encoded_point(&sc_p).expect("should be a valid point");
        let s_p = (sc_p * self.d_c.invert().expect("should be invertible")).to_encoded_point(true);

        // Use it to find the user ID point, if any.
        if let Some(hs_u) = bucket.get(&s_p).cloned() {
            // Hash the phone number and reduce it to a scalar.
            let h = Scalar::reduce_nonzero_bytes(&sha256(p.as_bytes()).into());

            // Unblind the user ID point.
            let hs_u = AffinePoint::from_encoded_point(&hs_u).expect("should be a valid point");
            let s_u = hs_u * h.invert().expect("should be invertible");

            // Return it.
            Some(s_u.to_affine().to_encoded_point(true))
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

/// Hashes `b` to a point on the P-256 curve using the method in RFC 9380 using SHA-256.
fn hash_to_curve(b: &[u8]) -> ProjectivePoint {
    NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[b], &[b"zk-cds-prototype"])
        .expect("should produce a valid point")
}

/// Hash `b` with SHA-256.
fn sha256(b: &[u8]) -> [u8; 32] {
    sha2::Sha256::new().chain_update(b).finalize().into()
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
