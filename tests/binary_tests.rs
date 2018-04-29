use std::fs::{DirEntry, File};
use std::io;
use std::io::prelude::*;
use std::ops::Drop;
use std::path::PathBuf;
use std::process::{Command, Output};
extern crate ca;
extern crate openssl;
use ca::CertContainer;
use openssl::pkcs12::Pkcs12;

#[test]
fn test_init() {
    let dir = TempDir::new("init");
    let output = run(dir.0.clone(), &["init"]);
    assert!(output.status.success());
    assert_eq!(0, output.stdout.len());
    assert_eq!(0, output.stderr.len());

    let mut keystore_path = dir.0.clone();
    keystore_path.push("keystore.p12");
    check_keystore(&keystore_path, "changeit", "root-ca");
}

#[test]
fn test_issue_intermediate() {
    let dir = TempDir::new("issue_intermediate");
    let output = run(dir.0.clone(), &["init"]);
    assert!(output.status.success());
    assert_eq!(0, output.stdout.len());
    assert_eq!(0, output.stderr.len());

    let output = run(dir.0.clone(), &["issue", "intermediate", "foo"]);
    assert!(output.status.success());

    let mut intermediate_keystore = dir.0.clone();
    intermediate_keystore.push("intermediate");
    intermediate_keystore.push("foo");
    let mut intermediate_issued = intermediate_keystore.clone();
    intermediate_issued.push("issued");
    intermediate_keystore.push("keystore.p12");

    check_keystore(&intermediate_keystore, "changeit", "foo");
    assert!(intermediate_issued.exists());

    let output = run(
        dir.0.clone(),
        &[
            "issue",
            "server",
            "--no-export",
            "-i",
            "foo",
            "www.example.com",
        ],
    );
    assert!(output.status.success());

    let entries = std::fs::read_dir(intermediate_issued).unwrap();
    let dir_vec: Vec<io::Result<DirEntry>> = entries.collect();
    assert_eq!(1, dir_vec.len());

    let output = run(dir.0.clone(), &["list", "--intermediate", "foo"]);
    assert!(output.status.success());

    assert_eq!(
        "server certificates\n  www.example.com\n",
        std::str::from_utf8(&output.stdout[..]).unwrap()
    );

    let output = run(
        dir.0.clone(),
        &["issue", "server", "--no-export", "test.example.com"],
    );
    assert!(output.status.success());

    let output = run(dir.0.clone(), &["list"]);
    assert!(output.status.success());

    assert_eq!(
        "intermediate certificates\n  foo\nserver certificates\n  test.example.com\n",
        std::str::from_utf8(&output.stdout[..]).unwrap()
    );
}



#[test]
fn test_export() {
    let dir = TempDir::new("export");
    let output = run(dir.0.clone(), &["init"]);
    assert!(output.status.success());
    assert_eq!(0, output.stdout.len());
    assert_eq!(0, output.stderr.len());

    let output = run(dir.0.clone(), &["issue", "intermediate", "foo"]);
    assert!(output.status.success());

    let mut intermediate_keystore = dir.0.clone();
    intermediate_keystore.push("intermediate");
    intermediate_keystore.push("foo");
    let mut intermediate_issued = intermediate_keystore.clone();
    intermediate_issued.push("issued");
    intermediate_keystore.push("keystore.p12");

    check_keystore(&intermediate_keystore, "changeit", "foo");
    assert!(intermediate_issued.exists());

    let output = run(
        dir.0.clone(),
        &[
            "issue",
            "server",
            "--no-export",
            "-i",
            "foo",
            "www.example.com",
        ],
    );
    assert!(output.status.success());

    let entries = std::fs::read_dir(intermediate_issued).unwrap();
    let dir_vec: Vec<io::Result<DirEntry>> = entries.collect();
    assert_eq!(1, dir_vec.len());

    let output = run(
        dir.0.clone(),
        &["issue", "server", "--no-export", "test.example.com"],
    );
    assert!(output.status.success());

    let output = run(
        dir.0.clone(),
        &["export","-o",dir.0.clone().to_str().unwrap(), "test.example.com"],
    );

    let mut export_tar = dir.0.clone();
    export_tar.push("test.example.com.tar");

    assert!(export_tar.exists());

let output = run(
        dir.0.clone(),
        &["export","-o",dir.0.clone().to_str().unwrap(), "-i","foo","www.example.com"],
    );


}


fn cleanup(_d: TempDir) {}

fn run(dir: PathBuf, args: &[&str]) -> Output {
    let mut bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    bin.push("target");
    bin.push("debug");
    bin.push("ca");
    let mut cmd = Command::new(bin);
    cmd.arg("-d");
    cmd.arg(dir.to_str().unwrap());
    for arg in args {
        cmd.arg(arg);
    }
    let mut output = cmd.output().expect("unable to run ca command");

    if !output.status.success() {
        println!("{}", std::str::from_utf8(&output.stdout[..]).unwrap());
        println!("{}", std::str::from_utf8(&output.stderr[..]).unwrap());
        panic!("ca command was not successfull");
    }
    output
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(test_name: &str) -> TempDir {
        let mut dir = std::env::temp_dir();
        dir.push(format!("ca-binary-test-{}", test_name));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("unable to create test directory");
        return TempDir(dir);
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn check_keystore(keystore_path: &PathBuf, pwd: &str, name: &str) {
    let testant = CertContainer::from_p12(load_keystore(&keystore_path), pwd)
        .expect("unable to load CA container");

    assert_eq!(name, &testant.name().expect("unable to get cert name"));
}

fn load_keystore(path: &PathBuf) -> Pkcs12 {
    assert!(path.exists());
    let mut keystore_der = Vec::new();
    let mut keystore_file = File::open(path).expect("unable to open keystore file");
    keystore_file
        .read_to_end(&mut keystore_der)
        .expect("unable to read keystore file");
    openssl::pkcs12::Pkcs12::from_der(&keystore_der[..]).expect("unable to load keystore from der")
}
