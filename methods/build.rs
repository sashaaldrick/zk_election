use std::{collections::HashMap, env, fs::File, io::Write, path::Path};

use risc0_build::{embed_methods_with_options, DockerOptions, GuestOptions};
use risc0_build_ethereum::generate_solidity_files;

fn main() {
    let current_dir = env::current_dir().unwrap();
    println!("cargo:warning=Current directory: {:?}", current_dir);

    // create directories if they don't exist
    let contracts_dir = current_dir.join("../contracts");
    let tests_dir = current_dir.join("../tests");
    
    std::fs::create_dir_all(&contracts_dir).unwrap();
    std::fs::create_dir_all(&tests_dir).unwrap();

    // use absolute paths
    let image_id_path = contracts_dir.join("ImageID.sol");
    let elf_path = tests_dir.join("Elf.sol");

    println!("cargo:warning=ImageID.sol path: {:?}", image_id_path);
    println!("cargo:warning=Elf.sol path: {:?}", elf_path);

    println!("cargo:rerun-if-env-changed=RISC0_USE_DOCKER");
    let use_docker = env::var("RISC0_USE_DOCKER").ok().map(|_| DockerOptions {
        root_dir: Some("../".into()),
    });

    let guests = embed_methods_with_options(HashMap::from([(
        "guests",
        GuestOptions {
            features: Vec::new(),
            use_docker,
        },
    )]));

    let solidity_opts = risc0_build_ethereum::Options::default()
        .with_image_id_sol_path(image_id_path.to_str().unwrap())
        .with_elf_sol_path(elf_path.to_str().unwrap());

    // try creating empty files first to verify permissions
    File::create(&image_id_path).unwrap();
    File::create(&elf_path).unwrap();

    generate_solidity_files(guests.as_slice(), &solidity_opts).unwrap();
}
