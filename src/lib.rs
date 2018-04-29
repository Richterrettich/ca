extern crate openssl;
extern crate tar;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use tar::{Builder, Header};

use openssl::rsa::Rsa;
use openssl::x509;
use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage,
                               SubjectAlternativeName, SubjectKeyIdentifier};

use openssl::nid::Nid;

use std::fs;
use std::fs::create_dir_all;
use std::io;
use std::io::prelude::*;
use std::net::IpAddr;
use std::path;
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, Box<std::error::Error>>;

pub fn mkdir_p<P: AsRef<Path>>(path: &P) -> io::Result<()> {
    if let Err(e) = create_dir_all(path) {
        if e.kind() != io::ErrorKind::AlreadyExists {
            return Err(e);
        }
    }
    Ok(())
}

pub struct CertContainer {
    pub key: PKey<Private>,
    pub chain: Vec<x509::X509>,
    pub cert: x509::X509,
    pub p12: Pkcs12,
    pub passwd: String,
}

impl CertContainer {
    pub fn load_intermediate<T>(dir: &Path, name: T, pwd: T) -> Result<Option<Self>>
    where
        T: AsRef<str> + std::clone::Clone,
    {
        let mut intermediate = PathBuf::from(dir);
        intermediate.push("intermediate");
        intermediate.push(name.as_ref());

        if !intermediate.exists() {
            return Ok(None);
        }
        intermediate.push("keystore.p12");
        return Ok(Some(CertContainer::load(intermediate, pwd)?));
    }

    pub fn from_pem<T>(
        key_pem: &[u8],
        cert_pem: &[u8],
        pwd: T,
        existing_pwd: Option<T>,
    ) -> Result<Self>
    where
        T: AsRef<str> + std::clone::Clone,
    {
        let cert = x509::X509::from_pem(cert_pem)?;
        let key = if existing_pwd.is_none() {
            openssl::pkey::PKey::private_key_from_pem(&key_pem[..])?
        } else {
            openssl::pkey::PKey::private_key_from_pem_passphrase(
                &key_pem[..],
                existing_pwd.unwrap().as_ref().as_bytes(),
            )?
        };

        let builder = Pkcs12::builder();

        let name = extract_name(cert.as_ref())?;
        let p12 = builder.build(pwd.as_ref(), name.as_ref(), key.as_ref(), cert.as_ref())?;
        Self::from_p12(p12, pwd)
    }

    pub fn generate<T>(name: T, duration: u32, pwd: T) -> Result<Self>
    where
        T: AsRef<str> + std::clone::Clone,
    {
        let mut x509_name_builder = x509::X509NameBuilder::new()?;

        x509_name_builder.append_entry_by_nid(Nid::COMMONNAME, name.as_ref())?;
        let x509_name = x509_name_builder.build();

        let (mut cert_builder, pkey) =
            Self::container_template(&x509_name, &x509_name, duration, 4096)?;

        cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        cert_builder.append_extension(KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?)?;

        let subject_key_identifier =
            SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
        cert_builder.append_extension(subject_key_identifier)?;

        let auth_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&cert_builder.x509v3_context(None, None))?;
        cert_builder.append_extension(auth_key_identifier)?;

        cert_builder.sign(&pkey, openssl::hash::MessageDigest::sha256())?;
        let cert = cert_builder.build();

        let builder = Pkcs12::builder();

        let p12 = builder.build(pwd.as_ref(), name.as_ref(), pkey.as_ref(), cert.as_ref())?;
        Self::from_p12(p12, pwd)
    }

    pub fn from_p12<T>(p12: Pkcs12, pwd: T) -> Result<Self>
    where
        T: AsRef<str> + std::clone::Clone,
    {
        let parsed_p12 = p12.parse(pwd.as_ref())?;

        let chain = if parsed_p12.chain.is_some() {
            parsed_p12.chain.unwrap().into_iter().collect()
        } else {
            Vec::new()
        };

        Ok(CertContainer {
            chain: chain,
            cert: parsed_p12.cert,
            key: parsed_p12.pkey,
            p12: p12,
            passwd: pwd.as_ref().to_string(),
        })
    }

    pub fn load<T, F>(path: F, pwd: T) -> Result<Self>
    where
        F: AsRef<path::Path>,
        T: AsRef<str> + std::clone::Clone,
    {
        let mut keystore_file = fs::File::open(path)?;
        let mut contents = vec![];
        keystore_file.read_to_end(&mut contents)?;
        Self::from_p12(Pkcs12::from_der(&contents)?, pwd)
    }

    pub fn save<F>(&self, path: F) -> Result<()>
    where
        F: AsRef<path::Path>,
    {
        let mut key_store_file = fs::File::create(path)?;

        let mut p12_builder = Pkcs12::builder();

        let mut stack = openssl::stack::Stack::new()?;

        for cert in self.chain.clone() {
            stack.push(cert)?;
        }
        p12_builder.ca(stack);
        let p12 = p12_builder.build(self.passwd.as_ref(), &self.name()?, &self.key, &self.cert)?;
        let raw_keystore = p12.to_der()?;
        key_store_file.write_all(&raw_keystore)?;
        Ok(())
    }

    pub fn sign(&self, req: x509::X509Req) -> Result<x509::X509> {
        panic!("unimplemented");
    }

    pub fn issue<T>(&self, duration: u32, sans: &[&str], pwd: T) -> Result<Self>
    where
        T: AsRef<str> + std::clone::Clone,
    {
        let mut name_builder = x509::X509NameBuilder::new()?;
        let name = sans[0];
        name_builder.append_entry_by_text("CN", name)?;
        let x509name = name_builder.build();
        let (mut cert_builder, key) =
            Self::container_template(&x509name, self.cert.subject_name(), duration, 2048)?;

        cert_builder.append_extension(BasicConstraints::new().build()?)?;

        cert_builder.append_extension(KeyUsage::new()
            .critical()
            .non_repudiation()
            .digital_signature()
            .key_encipherment()
            .build()?)?;

        let subject_key_identifier = SubjectKeyIdentifier::new()
            .build(&cert_builder.x509v3_context(Some(&self.cert), None))?;
        cert_builder.append_extension(subject_key_identifier)?;

        let auth_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&cert_builder.x509v3_context(Some(&self.cert), None))?;
        cert_builder.append_extension(auth_key_identifier)?;

        let mut san_builder = SubjectAlternativeName::new();
        for san in sans {
            let is_ip = san.parse::<IpAddr>().is_ok();
            if is_ip {
                san_builder.ip(san);
            } else {
                san_builder.dns(san);
            }
        }
        let sans = san_builder.build(&cert_builder.x509v3_context(Some(&self.cert), None))?;
        cert_builder.append_extension(sans)?;
        cert_builder.sign(&self.key, openssl::hash::MessageDigest::sha256())?;
        let cert = cert_builder.build();

        let p12 = self.new_p12(key, cert, pwd.as_ref(), name)?;

        Self::from_p12(p12, pwd)
    }

    fn new_p12(
        &self,
        key: openssl::pkey::PKey<Private>,
        cert: x509::X509,
        pwd: &str,
        name: &str,
    ) -> Result<Pkcs12> {
        let mut p12_builder = Pkcs12::builder();
        let mut chain = openssl::stack::Stack::new()?;
        chain.push(self.cert.clone())?;
        for cert in self.chain.clone() {
            chain.push(cert)?;
        }

        p12_builder.ca(chain);
        Ok(p12_builder.build(pwd.as_ref(), name, key.as_ref(), cert.as_ref())?)
    }

    pub fn issue_intermediate<T>(&self, name: T, duration: u32, pwd: T) -> Result<Self>
    where
        T: AsRef<str> + std::clone::Clone,
    {
        let mut name_builder = x509::X509NameBuilder::new()?;

        name_builder.append_entry_by_text("CN", name.as_ref())?;
        let x509name = name_builder.build();
        let (mut cert_builder, key) =
            Self::container_template(&x509name, self.cert.subject_name(), duration, 4096)?;
        cert_builder.set_issuer_name(self.cert.subject_name())?;
        cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        cert_builder.append_extension(KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?)?;

        let subject_key_identifier = SubjectKeyIdentifier::new()
            .build(&cert_builder.x509v3_context(Some(&self.cert), None))?;
        cert_builder.append_extension(subject_key_identifier)?;

        let auth_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&cert_builder.x509v3_context(Some(&self.cert), None))?;
        cert_builder.append_extension(auth_key_identifier)?;
        cert_builder.sign(&self.key, openssl::hash::MessageDigest::sha256())?;

        let cert = cert_builder.build();

        let p12 = self.new_p12(key, cert, pwd.as_ref(), name.as_ref())?;

        Self::from_p12(p12, pwd)
    }

    pub fn name(&self) -> Result<String> {
        extract_name(self.cert.as_ref())
    }

    pub fn export<T: io::Write>(&self, out_writer: T) -> Result<()> {
        let mut chain_pem: Vec<u8> = Vec::new();

        let mut chain = self.chain.clone();
        chain.insert(0, self.cert.clone());
        for cert in self.chain.clone() {
            let mut pem = cert.to_pem()?;
            chain_pem.append(&mut pem);
        }

        let mut builder = Builder::new(out_writer);
        for (path, data) in vec![
            ("certs/chain.pem", &chain_pem[..]),
            ("certs/cert.pem", &self.cert.to_pem()?[..]),
            ("private/keystore.p12", &self.p12.to_der()?[..]),
            ("private/key.pem", &self.key.private_key_to_pem_pkcs8()?[..]),
            ("private/key.der", &self.key.private_key_to_der()?[..]),
            ("private/passphrase.txt", &self.passwd.as_bytes()),
        ] {
            add_data_to_tar(path, &mut builder, data)?;
        }

        builder.finish()?;

        Ok(())
    }

    fn container_template(
        name: &x509::X509NameRef,
        issuer: &x509::X509NameRef,
        duration: u32,
        key_length: u32,
    ) -> Result<(x509::X509Builder, PKey<Private>)> {
        let priv_key = Rsa::generate(key_length)?;
        let mut cert_builder = x509::X509Builder::new()?;
        let key = PKey::from_rsa(priv_key)?;
        cert_builder.set_issuer_name(issuer)?;
        cert_builder.set_subject_name(name)?;
        let not_before = Asn1Time::days_from_now(0)?;
        cert_builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(duration)?;
        cert_builder.set_not_after(&not_after)?;
        cert_builder.set_pubkey(&key)?;
        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        cert_builder.set_serial_number(&serial_number)?;

        Ok((cert_builder, key))
    }
}

fn add_data_to_tar<T: io::Write>(path: &str, builder: &mut Builder<T>, data: &[u8]) -> Result<()> {
    let mut header = Header::new_gnu();
    header.set_path(path)?;

    header.set_mode(655);
    header.set_size(data.len() as u64);
    header.set_cksum();
    builder.append(&header, data)?;
    Ok(())
}

fn extract_name(cert: &x509::X509Ref) -> Result<String> {
    let raw_name = cert.subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .into_iter()
        .next()
        .unwrap()
        .data()
        .as_utf8()?;
    let name = raw_name.as_ref().chars().as_str().to_string();
    Ok(name)
}
