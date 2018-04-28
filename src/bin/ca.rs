extern crate ca;
extern crate clap;
extern crate openssl;

use clap::{App, Arg, SubCommand};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;

fn main() {
    let matches = App::new("CA")
                    .version("1.0.0") //TODO replace with cargo variable
                    .author("René Richter")
                    .about("A simple CA manager to generate and sign certificates and their private keys.")
                    .arg(
                        Arg::with_name("directory")
                                .short("d")
                                .long("directory")
                                .value_name("DIR")
                                .help("Sets a custom directory. Defaults to ~/.local/share/ca")
                                .takes_value(true)
                    )
                    .subcommand(
                        SubCommand::with_name("init")
                                    .about("initialize the CA")
                    )

                    .subcommand(
                        SubCommand::with_name("issue")
                                    .about("issues a new certificate")
                                    
                                    .subcommand(
                                        SubCommand::with_name("server")
                                         .arg(
                                            Arg::with_name("SANS")
                                                .help("subject alternative names for the certificate")
                                                .multiple(true)
                                        )
                                        .arg(
                                        Arg::with_name("intermediate")
                                            .help("use an intermediate certificate to sign")
                                            .short("i")
                                            .long("intermediate")
                                            .takes_value(true)
                                    )
                                    .arg(
                                        Arg::with_name("duration")
                                            .help("the duration for the certificate in days (default 10950)")
                                            .short("d")
                                            .long("duration")
                                            .takes_value(true)
                                    )
                                    .arg(
                                        Arg::with_name("passwd")
                                            .help("the password for the new keystore (default: changeit)")
                                            .short("p")
                                            .long("password")
                                            .takes_value(true)
                                    )
                                    .arg(
                                        Arg::with_name("ca-pwd")
                                            .help("the password for the signing CA (default: changeit)")
                                            .long("ca-pwd")
                                            .takes_value(true)
                                    )
                                    )
                                    .subcommand(
                                         SubCommand::with_name("intermediate")
                                                .about("create an intermediate CA")
                                                .arg(
                                                    Arg::with_name("NAME")
                                                        .help("name of the intermediate CA")
                                                )
                                                .arg(
                                        Arg::with_name("intermediate")
                                            .help("use an intermediate certificate to sign")
                                            .short("i")
                                            .long("intermediate")
                                            .takes_value(true)
                                    )
                                    .arg(
                                        Arg::with_name("duration")
                                            .help("the duration for the certificate in days (default 10950)")
                                            .short("d")
                                            .long("duration")
                                            .takes_value(true)
                                    )
                                    .arg(
                                        Arg::with_name("passwd")
                                            .help("the password for the new keystore (default: changeit)")
                                            .short("p")
                                            .long("password")
                                            .takes_value(true)
                                    )
                                    .arg(
                                        Arg::with_name("ca-pwd")
                                            .help("the password for the signing CA (default: changeit)")
                                            .long("ca-pwd")
                                            .takes_value(true)
                                    )
                                    )
                    )
                    .subcommand(
                        SubCommand::with_name("import")
                                    .about("import a CA")
                                    .arg(
                                        Arg::with_name("password")
                                            .short("p")
                                            .long("password")
                                            .help("password of the key file")
                                            .takes_value(true)
                                            .default_value("changeit")
                                    )
                                    .arg(
                                        Arg::with_name("import-password")
                                            .long("import-password")
                                            .help("existing password of the key file")
                                            .takes_value(true)
                                    )
                                    .arg(
                                        Arg::with_name("key")
                                            .help("path to the CA private key pem file")
                                            .takes_value(true)
                                            .required(true)
                                    )
                                    .arg(
                                        Arg::with_name("cert")
                                            .help("path to the CA certificate pem file")
                                            .takes_value(true)
                                            .required(true)
                                    )
                    )
                    .subcommand(
                        SubCommand::with_name("list")
                                    .arg(
                                        Arg::with_name("intermediate")
                                                .short("i")
                                                .long("intermediate")
                                    )
                    )
                    .get_matches();

    let dir = if matches.is_present("directory") {
        matches.value_of("directory").unwrap().parse().unwrap()
    } else {
        match env::home_dir() {
            Some(d) => {
                let mut home_dir = std::path::PathBuf::from(d.to_string_lossy().to_owned().to_string());
                home_dir.push(".local");
                home_dir.push("ca");
                home_dir
            },
            None => panic!("no directory parameter provided and no home directory found. Please provide a directory parameter."),
        }
    };

    let result = match matches.subcommand() {
        ("init", Some(init_cmd)) => init_ca(init_cmd, dir),
        ("issue", Some(issue_cmd)) => issue(issue_cmd, dir),
        ("import", Some(import_cmd)) => import(
            dir,
            import_cmd.value_of("key").unwrap(),
            import_cmd.value_of("cert").unwrap(),
            import_cmd.value_of("password").unwrap(),
            import_cmd.value_of("import-password"),
        ),
        _ => panic!("invalid subcommand"),
    };

    if result.is_err() {
        println!("an error occred: {}", result.err().unwrap());
        std::process::exit(1);
    }
}

fn import(
    mut dir: std::path::PathBuf,
    key: &str,
    cert: &str,
    new_pwd: &str,
    existing_pwd: Option<&str>,
) -> ca::Result<()> {
    let mut key_file = File::open(key)?;
    let mut key_pem = Vec::new();
    key_file.read_to_end(&mut key_pem)?;
    let mut cert_file = File::open(cert)?;
    let mut cert_pem = Vec::new();
    cert_file.read_to_end(&mut cert_pem)?;

    dir.push("keystore.p12");

    let container =
        ca::CertContainer::from_pem(&key_pem[..], &cert_pem[..], new_pwd, existing_pwd)?;

    container.save(dir)?;

    Ok(())
}

fn issue(issue_cmd: &clap::ArgMatches, dir: std::path::PathBuf) -> ca::Result<()> {
    match issue_cmd.subcommand() {
        ("intermediate", Some(ic)) => issue_intermediate_cmd(ic, dir),
        ("server", Some(sc)) => issue_server_cmd(sc, dir),
        _ => {
            println!("{}", issue_cmd.usage());
            std::process::exit(1)
        }
    }
}

fn issue_intermediate_cmd(cmd: &clap::ArgMatches, mut dir: std::path::PathBuf) -> ca::Result<()> {
    let possible_intermediate = cmd.value_of("intermediate");
    let ca_pwd = cmd.value_of("ca-pwd").unwrap_or("changeit");
    let pwd = cmd.value_of("pwd").unwrap_or("changeit");
    let duration = cmd.value_of("duration")
        .unwrap_or("10950")
        .parse::<u32>()
        .expect("invalid format for duration: expected positive integer");
    let container = load_ca(dir.clone(), ca_pwd, possible_intermediate)?;

    let name = cmd.value_of("NAME").unwrap();
    dir.push("intermediate");
    dir.push(&name);
    create_ca_directories(dir.clone())?;
    dir.push("keystore.p12");
    let issued_cert = container.issue_intermediate(name, duration, pwd)?;

    issued_cert.save(dir)?;
    Ok(())
}

fn issue_server_cmd(cmd: &clap::ArgMatches, mut dir: std::path::PathBuf) -> ca::Result<()> {
    let possible_intermediate = cmd.value_of("intermediate");
    let ca_pwd = cmd.value_of("ca-pwd").unwrap_or("changeit");
    let pwd = cmd.value_of("pwd").unwrap_or("changeit");
    let duration = cmd.value_of("duration")
        .unwrap_or("10950")
        .parse::<u32>()
        .expect("invalid format for duration: expected positive integer");
    let container = load_ca(dir.clone(), ca_pwd, possible_intermediate)?;

    let sans: Vec<&str> = cmd.values_of("SANS").unwrap().collect();

    let cert = container.issue(duration, &sans, pwd)?;
    dir.push("issued");
    dir.push(format!("{}.p12", cert.name()?));

    cert.save(dir)?;
    let mut export = env::current_dir()?;
    export.push(format!("{}.tar", cert.name()?));
    let export_file = std::fs::File::create(export)?;
    cert.export(export_file)?;
    Ok(())
}

fn load_ca(
    mut dir: std::path::PathBuf,
    pwd: &str,
    possible_intermediate: Option<&str>,
) -> ca::Result<ca::CertContainer> {
    if let Some(intermediate) = possible_intermediate {
        let possible_container = ca::CertContainer::find_intermediate(&dir, intermediate, pwd)?;
        if possible_container.is_none() {
            let err: Box<Error> =
                From::from(format!("could not find intermediate ca {}", intermediate));
            return Err(err);
        }
        Ok(possible_container.unwrap())
    } else {
        dir.push("keystore.p12");
        ca::CertContainer::load(dir, pwd)
    }
}

fn init_ca(
    init_cmd: &clap::ArgMatches,
    dir: std::path::PathBuf,
) -> Result<(), Box<std::error::Error>> {
    let pwd = init_cmd.value_of("passwd").unwrap_or("changeit");
    let duration = init_cmd
        .value_of("duration")
        .unwrap_or("10950")
        .parse::<u32>()
        .expect("invalid format for duration: expected positive integer");
    let common_name = init_cmd.value_of("name").unwrap_or("root-ca");
    let container = ca::CertContainer::generate(common_name, duration, pwd)?;
    let mut keystore_path = dir.clone();
    create_ca_directories(dir)?;
    keystore_path.push("keystore.p12");
    container.save(keystore_path)?;
    Ok(())
}

fn create_ca_directories(dir: std::path::PathBuf) -> Result<(), Box<std::error::Error>> {
    ca::mkdir_p(&dir)?;
    let mut issued_dir = dir.clone();
    issued_dir.push("issued");
    ca::mkdir_p(&issued_dir)?;
    let mut intermediate_dir = dir.clone();
    intermediate_dir.push("intermediate");
    ca::mkdir_p(&intermediate_dir)?;
    Ok(())
}
