use crate::os_fingerprint::ttl_analyzer::OsSignature;
use std::collections::HashMap;

pub fn create_linux_signatures() -> Vec<OsSignature> {
    vec![
        OsSignature {
            name: "Linux".to_string(),
            version: Some("Generic".to_string()),
            ttl_values: vec![64],
            window_sizes: vec![5840, 5792, 14600, 29200],
            tcp_options: vec![
                "MSS".to_string(),
                "SACK".to_string(),
                "TS".to_string(),
                "NOP".to_string(),
                "WS".to_string(),
            ],
            confidence_weight: 0.9,
        },
        OsSignature {
            name: "Linux".to_string(),
            version: Some("Ubuntu".to_string()),
            ttl_values: vec![64],
            window_sizes: vec![29200, 14600],
            tcp_options: vec![
                "MSS".to_string(),
                "SACK".to_string(),
                "TS".to_string(),
                "NOP".to_string(),
                "WS".to_string(),
            ],
            confidence_weight: 0.95,
        },
    ]
}

pub fn create_windows_signatures() -> Vec<OsSignature> {
    vec![
        OsSignature {
            name: "Windows".to_string(),
            version: Some("10/11".to_string()),
            ttl_values: vec![128],
            window_sizes: vec![65535, 8192],
            tcp_options: vec![
                "MSS".to_string(),
                "NOP".to_string(),
                "WS".to_string(),
                "SACK".to_string(),
            ],
            confidence_weight: 0.9,
        },
        OsSignature {
            name: "Windows".to_string(),
            version: Some("Server".to_string()),
            ttl_values: vec![128],
            window_sizes: vec![65535, 16384],
            tcp_options: vec![
                "MSS".to_string(),
                "NOP".to_string(),
                "WS".to_string(),
                "SACK".to_string(),
            ],
            confidence_weight: 0.85,
        },
        OsSignature {
            name: "Windows".to_string(),
            version: Some("Legacy".to_string()),
            ttl_values: vec![128],
            window_sizes: vec![64240, 65535],
            tcp_options: vec!["MSS".to_string(), "NOP".to_string()],
            confidence_weight: 0.8,
        },
    ]
}

pub fn create_macos_signatures() -> Vec<OsSignature> {
    vec![OsSignature {
        name: "macOS".to_string(),
        version: Some("Modern".to_string()),
        ttl_values: vec![64],
        window_sizes: vec![65535],
        tcp_options: vec![
            "MSS".to_string(),
            "NOP".to_string(),
            "WS".to_string(),
            "TS".to_string(),
            "SACK".to_string(),
        ],
        confidence_weight: 0.9,
    }]
}

pub fn create_freebsd_signatures() -> Vec<OsSignature> {
    vec![OsSignature {
        name: "FreeBSD".to_string(),
        version: None,
        ttl_values: vec![64, 255],
        window_sizes: vec![65535, 32768],
        tcp_options: vec![
            "MSS".to_string(),
            "WS".to_string(),
            "SACK".to_string(),
            "TS".to_string(),
        ],
        confidence_weight: 0.85,
    }]
}

pub fn create_embedded_signatures() -> Vec<OsSignature> {
    vec![OsSignature {
        name: "Embedded/IoT".to_string(),
        version: None,
        ttl_values: vec![32, 48, 255],
        window_sizes: vec![512, 1024, 2048, 4096, 8760],
        tcp_options: vec!["MSS".to_string()],
        confidence_weight: 0.7,
    }]
}

pub fn initialize_signature_database() -> HashMap<String, Vec<OsSignature>> {
    let mut db = HashMap::new();

    db.insert("Linux".to_string(), create_linux_signatures());
    db.insert("Windows".to_string(), create_windows_signatures());
    db.insert("macOS".to_string(), create_macos_signatures());
    db.insert("FreeBSD".to_string(), create_freebsd_signatures());
    db.insert("Embedded".to_string(), create_embedded_signatures());

    db
}
