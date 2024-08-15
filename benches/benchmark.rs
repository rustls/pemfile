use std::io::BufReader;

use criterion::{criterion_group, criterion_main, Criterion};

fn bench(c: &mut Criterion) {
    // typical server workload
    c.bench_function("3 certificates", |b| {
        b.iter(|| {
            let data = include_bytes!("../tests/data/certificate.chain.pem");
            let mut reader = BufReader::new(&data[..]);
            assert_eq!(
                rustls_pemfile::certs(&mut reader)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
                    .len(),
                3
            );
        })
    });

    // one of every supported type
    c.bench_function("zen", |b| {
        b.iter(|| {
            let data = include_bytes!("../tests/data/zen.pem");
            let mut reader = BufReader::new(&data[..]);
            rustls_pemfile::read_all(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        })
    });

    // typical client workload
    c.bench_function("ca-certs", |b| {
        b.iter(|| {
            let data = include_bytes!("../tests/data/ca-certs.pem");
            let mut reader = BufReader::new(&data[..]);
            rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
