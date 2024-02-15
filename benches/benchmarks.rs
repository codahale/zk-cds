use std::collections::HashMap;

use criterion::{criterion_group, criterion_main, Criterion};
use p256::elliptic_curve::rand_core::CryptoRngCore;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use uuid::Uuid;
use zk_cds::{Client, Server};

fn build(c: &mut Criterion) {
    let mut g = c.benchmark_group("build");
    g.throughput(criterion::Throughput::Elements(100));
    g.bench_function("100", |b| {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let id = Uuid::new_v4();
        b.iter(|| create_server(rng.clone(), 100, id));
    });
    g.finish();
}

fn lookup(c: &mut Criterion) {
    let mut g = c.benchmark_group("lookup");
    g.throughput(criterion::Throughput::Elements(100));
    g.bench_function("100", |b| {
        let rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let id = Uuid::new_v4();
        let server = create_server(rng.clone(), 100, id);
        let client = Client::new(rng.clone());
        b.iter(|| {
            let (prefix, c_p) = client.request_phone_number(22);
            let bucket = server.find_bucket(prefix);
            let sc_p = server.blind_phone_number(&c_p);
            client.find_user_id(&sc_p, &bucket, 1234567890).expect("should be a valid phone number")
        });
    });
    g.finish();
}

fn create_server(rng: impl CryptoRngCore, n: usize, id: Uuid) -> Server {
    let mut users = HashMap::new();
    for i in 0..(n as u64) {
        users.insert(i, id);
    }
    Server::new(rng, &users)
}

criterion_group!(benches, build, lookup);
criterion_main!(benches);
