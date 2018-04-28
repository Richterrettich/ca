extern crate ca;
extern crate openssl;
extern crate tar;
use std::io::prelude::*;

#[test]
fn ca() {
    let (container, mut dir) = prepare_ca("ca");

    dir.push("keystore.p12");
    let new_container = ca::CertContainer::load(&dir, "changeit").unwrap();

    assert!(
        container
            .cert
            .public_key()
            .unwrap()
            .public_eq(&new_container.cert.public_key().unwrap())
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn issue() {
    let (container, dir) = prepare_ca("issue");
    let issued = container
        .issue(365 * 10, &["www.example.com"], "changeit")
        .unwrap();

    assert!(
        issued.chain[0]
            .public_key()
            .unwrap()
            .public_eq(&container.cert.public_key().unwrap())
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn export() {
    let (container, mut dir) = prepare_ca("export");
    let issued = container
        .issue(365 * 10, &["www.example.com"], "changeit")
        .unwrap();

    dir.push("test.tar");

    let mut tar_file = std::fs::File::create(dir.clone()).unwrap();

    issued.export(&mut tar_file).unwrap();
    tar_file.flush().unwrap();

    let new_tar_file = std::fs::File::open(dir.clone()).unwrap();

    let mut a = tar::Archive::new(new_tar_file);
    let mut present_map = std::collections::HashMap::new();

    for path in vec![
        "certs/chain.pem",
        "certs/cert.pem",
        "private/key.pem",
        "private/key.der",
        "private/keystore.p12",
        "private/passphrase.txt",
    ] {
        present_map.insert(path.to_string(), false);
    }
    for file in a.entries().unwrap() {
        let mut file = file.unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let p = file.header().path().unwrap();
        let path = p.to_str().unwrap();

        present_map.insert(String::from(path), true);
        match path {
            "certs/chain.pem" => {
                openssl::x509::X509::stack_from_pem(&mut data).unwrap();
            }
            "certs/cert.pem" => {
                openssl::x509::X509::from_pem(&mut data).unwrap();
            }
            "private/keystore.p12" => {
                openssl::pkcs12::Pkcs12::from_der(&mut data).unwrap();
            }
            "private/key.pem" => {
                openssl::pkey::PKey::private_key_from_pem(&mut data).unwrap();
            }
            "private/key.der" => {
                openssl::pkey::PKey::private_key_from_der(&mut data).unwrap();
            }
            "private/passphrase.txt" => {
                assert_eq!("changeit", std::str::from_utf8(&data[..]).unwrap());
            }
            _ => panic!(format!("unrecognized path {}", path)),
        }
    }
    for (_k, present) in present_map {
        assert!(present);
    }
    std::fs::remove_dir_all(&dir).ok();
}



fn prepare_ca(test_name: &str) -> (ca::CertContainer, std::path::PathBuf) {
    let container = ca::CertContainer::generate("root", 365 * 10, "changeit").unwrap();
    assert_eq!("root", &container.name().unwrap());
    let mut dir = std::env::temp_dir();
    dir.push(format!("ca_test_{}", test_name));
    std::fs::remove_dir_all(&dir).ok();
    ca::mkdir_p(&dir).unwrap();
    let mut keystore = dir.clone();
    keystore.push("keystore.p12");
    container.save(&keystore).unwrap();
    (container, dir)
}
