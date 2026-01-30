// SPDX-License-Identifier: MIT
// Benchmarks for Quantum-Safe Storage Protocol
//
// Run with: cargo bench -p citrate-storage

#[cfg(test)]
mod bench_tests {
    use crate::crypto::quantum_safe::{HybridKEM, QuantumSafeConfig, SecurityLevel};
    use crate::crypto::database_encryption::{DatabaseEncryptionConfig, EncryptedDatabase};
    use std::time::Instant;

    /// Benchmark key generation
    #[test]
    fn bench_keypair_generation() {
        let config = QuantumSafeConfig::default();
        let kem = HybridKEM::new(config);

        let iterations = 10;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = kem.generate_keypair().unwrap();
        }

        let elapsed = start.elapsed();
        let per_op = elapsed / iterations;

        println!("\n=== Keypair Generation Benchmark ===");
        println!("Total: {:?} for {} iterations", elapsed, iterations);
        println!("Per operation: {:?}", per_op);
        println!("Operations/sec: {:.2}", 1.0 / per_op.as_secs_f64());
    }

    /// Benchmark encapsulation
    #[test]
    fn bench_encapsulation() {
        let config = QuantumSafeConfig::default();
        let kem = HybridKEM::new(config);
        let keypair = kem.generate_keypair().unwrap();

        let iterations = 100;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = kem.encapsulate(&keypair.public_key).unwrap();
        }

        let elapsed = start.elapsed();
        let per_op = elapsed / iterations;

        println!("\n=== Encapsulation Benchmark ===");
        println!("Total: {:?} for {} iterations", elapsed, iterations);
        println!("Per operation: {:?}", per_op);
        println!("Operations/sec: {:.2}", 1.0 / per_op.as_secs_f64());
    }

    /// Benchmark decapsulation
    #[test]
    fn bench_decapsulation() {
        let config = QuantumSafeConfig::default();
        let kem = HybridKEM::new(config);
        let keypair = kem.generate_keypair().unwrap();
        let (encap, _) = kem.encapsulate(&keypair.public_key).unwrap();

        let iterations = 100;
        let start = Instant::now();

        for _ in 0..iterations {
            let _ = kem.decapsulate(&keypair.secret_key, &encap).unwrap();
        }

        let elapsed = start.elapsed();
        let per_op = elapsed / iterations;

        println!("\n=== Decapsulation Benchmark ===");
        println!("Total: {:?} for {} iterations", elapsed, iterations);
        println!("Per operation: {:?}", per_op);
        println!("Operations/sec: {:.2}", 1.0 / per_op.as_secs_f64());
    }

    /// Benchmark full encryption cycle
    #[test]
    fn bench_encrypt_decrypt_cycle() {
        let config = QuantumSafeConfig::default();
        let kem = HybridKEM::new(config);
        let keypair = kem.generate_keypair().unwrap();

        // Test with various data sizes
        let sizes = [64, 1024, 16384, 65536, 1048576]; // 64B to 1MB

        println!("\n=== Encrypt/Decrypt Benchmark by Data Size ===");
        println!("{:>12} {:>15} {:>15} {:>15}", "Size", "Encrypt", "Decrypt", "Throughput");

        for size in sizes {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let aad = b"benchmark-test";

            // Warm up
            let encrypted = kem.encrypt(&keypair.public_key, &data, aad).unwrap();
            let _ = kem.decrypt(&keypair.secret_key, &encrypted, aad).unwrap();

            let iterations = if size > 100_000 { 10 } else { 50 };

            // Benchmark encryption
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = kem.encrypt(&keypair.public_key, &data, aad).unwrap();
            }
            let encrypt_time = start.elapsed() / iterations;

            // Benchmark decryption
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = kem.decrypt(&keypair.secret_key, &encrypted, aad).unwrap();
            }
            let decrypt_time = start.elapsed() / iterations;

            let throughput_mbps = (size as f64 / 1_000_000.0) / encrypt_time.as_secs_f64();

            println!(
                "{:>12} {:>15.3?} {:>15.3?} {:>12.2} MB/s",
                format_size(size),
                encrypt_time,
                decrypt_time,
                throughput_mbps
            );
        }
    }

    /// Benchmark database encryption layer
    #[test]
    fn bench_database_encryption() {
        let config = DatabaseEncryptionConfig::default();
        let mut db = EncryptedDatabase::new(config);
        db.initialize(b"benchmark-password-123").unwrap();

        let sizes = [64, 1024, 16384];
        let iterations = 100;

        println!("\n=== Database Encryption Layer Benchmark ===");
        println!("{:>12} {:>15} {:>15}", "Size", "Encrypt", "Decrypt");

        for size in sizes {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let cf = "state";
            let key = b"test-key";

            // Warm up
            let encrypted = db.encrypt(cf, key, &data).unwrap();
            let _ = db.decrypt(cf, key, &encrypted.data).unwrap();

            // Benchmark encryption
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = db.encrypt(cf, key, &data).unwrap();
            }
            let encrypt_time = start.elapsed() / iterations;

            // Benchmark decryption
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = db.decrypt(cf, key, &encrypted.data).unwrap();
            }
            let decrypt_time = start.elapsed() / iterations;

            println!(
                "{:>12} {:>15.3?} {:>15.3?}",
                format_size(size),
                encrypt_time,
                decrypt_time
            );
        }
    }

    /// Benchmark all security levels
    #[test]
    fn bench_security_levels() {
        println!("\n=== Security Level Comparison ===");
        println!("{:>10} {:>15} {:>15} {:>15}", "Level", "KeyGen", "Encap", "Decap");

        for level in [SecurityLevel::Standard, SecurityLevel::High, SecurityLevel::Maximum] {
            let config = QuantumSafeConfig {
                security_level: level,
                ..Default::default()
            };
            let kem = HybridKEM::new(config);

            // Benchmark keygen
            let start = Instant::now();
            let keypair = kem.generate_keypair().unwrap();
            let keygen_time = start.elapsed();

            // Benchmark encap
            let iterations = 50;
            let start = Instant::now();
            let mut encap = None;
            for _ in 0..iterations {
                let (e, _) = kem.encapsulate(&keypair.public_key).unwrap();
                encap = Some(e);
            }
            let encap_time = start.elapsed() / iterations;

            // Benchmark decap
            let encap = encap.unwrap();
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = kem.decapsulate(&keypair.secret_key, &encap).unwrap();
            }
            let decap_time = start.elapsed() / iterations;

            println!(
                "{:>10} {:>15.3?} {:>15.3?} {:>15.3?}",
                format!("{:?}", level),
                keygen_time,
                encap_time,
                decap_time
            );
        }
    }

    fn format_size(bytes: usize) -> String {
        if bytes >= 1_048_576 {
            format!("{} MB", bytes / 1_048_576)
        } else if bytes >= 1024 {
            format!("{} KB", bytes / 1024)
        } else {
            format!("{} B", bytes)
        }
    }
}
