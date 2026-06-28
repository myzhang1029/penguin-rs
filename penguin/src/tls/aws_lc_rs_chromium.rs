//! Mimic Chromium's TLS fingerprint.
//
// SPDX-License-Identifier: Apache-2.0 OR GPL-3.0-or-later

use rustls::crypto::aws_lc_rs::{cipher_suite, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup, WebPkiSupportedAlgorithms};
use rustls::{
    CipherSuite, CipherSuiteCommon, SignatureScheme, SupportedCipherSuite, Tls12CipherSuite,
};
use std::sync::LazyLock;
use webpki::aws_lc_rs as webpki_algs;

// Actually implements TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, but advertises itself as TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
static TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: LazyLock<Tls12CipherSuite> = LazyLock::new(|| {
    let SupportedCipherSuite::Tls12(actual) = cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    else {
        panic!("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 should be Tls12");
    };
    Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            ..actual.common
        },
        ..*actual
    }
});

// Actually implements TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, but advertises itself as TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
static TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: LazyLock<Tls12CipherSuite> = LazyLock::new(|| {
    let SupportedCipherSuite::Tls12(actual) = cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    else {
        panic!("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 should be Tls12");
    };
    Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            ..actual.common
        },
        ..*actual
    }
});

// Actually implements TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, but advertises itself as TLS_RSA_WITH_AES_128_GCM_SHA256
static TLS_RSA_WITH_AES_128_GCM_SHA256: LazyLock<Tls12CipherSuite> = LazyLock::new(|| {
    let SupportedCipherSuite::Tls12(actual) = cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    else {
        panic!("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 should be Tls12");
    };
    Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
            ..actual.common
        },
        ..*actual
    }
});

// Actually implements TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, but advertises itself as TLS_RSA_WITH_AES_256_GCM_SHA384
static TLS_RSA_WITH_AES_256_GCM_SHA384: LazyLock<Tls12CipherSuite> = LazyLock::new(|| {
    let SupportedCipherSuite::Tls12(actual) = cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    else {
        panic!("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 should be Tls12");
    };
    Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
            ..actual.common
        },
        ..*actual
    }
});

// Actually implements TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, but advertises itself as TLS_RSA_WITH_AES_128_CBC_SHA
static TLS_RSA_WITH_AES_128_CBC_SHA: LazyLock<Tls12CipherSuite> = LazyLock::new(|| {
    let SupportedCipherSuite::Tls12(actual) = cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    else {
        panic!("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 should be Tls12");
    };
    Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
            ..actual.common
        },
        ..*actual
    }
});

// Actually implements TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, but advertises itself as TLS_RSA_WITH_AES_256_CBC_SHA
static TLS_RSA_WITH_AES_256_CBC_SHA: LazyLock<Tls12CipherSuite> = LazyLock::new(|| {
    let SupportedCipherSuite::Tls12(actual) = cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    else {
        panic!("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 should be Tls12");
    };
    Tls12CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
            ..actual.common
        },
        ..*actual
    }
});

// Cipher Suites
static CIPHER_SUITES: LazyLock<[SupportedCipherSuite; 15]> = LazyLock::new(|| {
    [
        // TLS1.3 suites
        cipher_suite::TLS13_AES_128_GCM_SHA256,
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        // TLS1.2 suites
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
        SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
        SupportedCipherSuite::Tls12(&TLS_RSA_WITH_AES_128_GCM_SHA256),
        SupportedCipherSuite::Tls12(&TLS_RSA_WITH_AES_256_GCM_SHA384),
        SupportedCipherSuite::Tls12(&TLS_RSA_WITH_AES_128_CBC_SHA),
        SupportedCipherSuite::Tls12(&TLS_RSA_WITH_AES_256_CBC_SHA),
    ]
});

// Extension: supported_groups
const KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    kx_group::X25519MLKEM768,
    kx_group::X25519,
    kx_group::SECP256R1,
    kx_group::SECP384R1,
];

const SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        webpki_algs::ECDSA_P256_SHA256,
        webpki_algs::ECDSA_P256_SHA384,
        webpki_algs::ECDSA_P256_SHA512,
        webpki_algs::ECDSA_P384_SHA256,
        webpki_algs::ECDSA_P384_SHA384,
        webpki_algs::ECDSA_P384_SHA512,
        webpki_algs::ECDSA_P521_SHA256,
        webpki_algs::ECDSA_P521_SHA384,
        webpki_algs::ECDSA_P521_SHA512,
        webpki_algs::ED25519,
        webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
        webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512,
        webpki_algs::RSA_PKCS1_2048_8192_SHA256_ABSENT_PARAMS,
        webpki_algs::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
        webpki_algs::RSA_PKCS1_2048_8192_SHA512_ABSENT_PARAMS,
    ],
    // Extension: signature_algorithms
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[
                webpki_algs::ECDSA_P256_SHA256,
                webpki_algs::ECDSA_P384_SHA256,
                webpki_algs::ECDSA_P521_SHA256,
            ],
        ),
        (
            SignatureScheme::RSA_PSS_SHA256,
            &[webpki_algs::RSA_PSS_2048_8192_SHA256_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA256],
        ),
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[
                webpki_algs::ECDSA_P384_SHA384,
                webpki_algs::ECDSA_P256_SHA384,
                webpki_algs::ECDSA_P521_SHA384,
            ],
        ),
        (
            SignatureScheme::RSA_PSS_SHA384,
            &[webpki_algs::RSA_PSS_2048_8192_SHA384_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA384,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA384],
        ),
        (
            SignatureScheme::RSA_PSS_SHA512,
            &[webpki_algs::RSA_PSS_2048_8192_SHA512_LEGACY_KEY],
        ),
        (
            SignatureScheme::RSA_PKCS1_SHA512,
            &[webpki_algs::RSA_PKCS1_2048_8192_SHA512],
        ),
        /*
        (
            SignatureScheme::ECDSA_NISTP521_SHA512,
            &[
                webpki_algs::ECDSA_P521_SHA512,
                webpki_algs::ECDSA_P384_SHA512,
                webpki_algs::ECDSA_P256_SHA512,
            ],
        ),
        (SignatureScheme::ED25519, &[webpki_algs::ED25519]),
        */
    ],
};

/// A `CryptoProvider` backed by aws-lc-rs and configured to produce a Chromium-like
/// TLS fingerprint.
pub fn chromium_like_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: CIPHER_SUITES.to_vec(),
        kx_groups: KX_GROUPS.to_vec(),
        signature_verification_algorithms: SUPPORTED_SIG_ALGS,
        secure_random: rustls::crypto::aws_lc_rs::default_provider().secure_random,
        key_provider: rustls::crypto::aws_lc_rs::default_provider().key_provider,
    }
}
