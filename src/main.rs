use std::{
    collections::HashSet,
    env::consts::ARCH,
    fs::{self, File, Permissions},
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use async_recursion::async_recursion;
use clap::Parser;
use cli::Args;
use flate2::read::MultiGzDecoder;
use reqwest::Client;
use tar::{Archive, Builder};
use walkdir::WalkDir;
use zstd::stream::Encoder;

mod cli;

pub const BASE_URL: &str = "https://dl-cdn.alpinelinux.org/alpine/edge";

#[derive(Eq, PartialEq, Hash, Clone)]
struct PackageMetadata {
    noidea: String,
    package: String,
    version: String,
    arch: String,
    size: u32,
    i: u32,
    description: String,
    url: String,
    license: String,
    output: String,
    maintainer: String,
    timestamp: u64,
    checksum: String,
    k: u32,
    depends: Vec<String>,
    provides: Vec<String>,
}

struct Registry {
    main: Vec<PackageMetadata>,
    community: Vec<PackageMetadata>,
    testing: Vec<PackageMetadata>,
}

#[derive(Eq, PartialEq, Hash, Clone)]
struct PackageWithSource {
    package: PackageMetadata,
    source: String,
}

fn parse_metadata(input: &str) -> PackageMetadata {
    let mut metadata = PackageMetadata {
        noidea: String::new(),
        package: String::new(),
        version: String::new(),
        arch: String::new(),
        size: 0,
        i: 0,
        description: String::new(),
        url: String::new(),
        license: String::new(),
        output: String::new(),
        maintainer: String::new(),
        timestamp: 0,
        checksum: String::new(),
        k: 0,
        depends: Vec::new(),
        provides: Vec::new(),
    };

    for line in input.lines() {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() == 2 {
            let key = parts[0].trim();
            let value = parts[1].trim();

            match key {
                "C" => metadata.noidea = value.to_string(),
                "P" => metadata.package = value.to_string(),
                "V" => metadata.version = value.to_string(),
                "A" => metadata.arch = value.to_string(),
                "S" => metadata.size = value.parse().unwrap(),
                "I" => metadata.i = value.parse().unwrap(),
                "T" => metadata.description = value.to_string(),
                "U" => metadata.url = value.to_string(),
                "L" => metadata.license = value.to_string(),
                "o" => metadata.output = value.to_string(),
                "m" => metadata.maintainer = value.to_string(),
                "t" => metadata.timestamp = value.parse().unwrap(),
                "c" => metadata.checksum = value.to_string(),
                "k" => metadata.k = value.parse().unwrap(),
                "D" => metadata.depends = value.split_whitespace().map(String::from).collect(),
                "p" => metadata.provides = value.split_whitespace().map(String::from).collect(),
                _ => {}
            }
        }
    }

    metadata
}

fn full_metadata(input: &str) -> Vec<PackageMetadata> {
    let mut packages = Vec::new();
    let mut current_metadata = String::new();

    for line in input.lines() {
        if line.trim().is_empty() {
            if !current_metadata.is_empty() {
                packages.push(parse_metadata(&current_metadata));
                current_metadata.clear();
            }
        } else {
            current_metadata.push_str(line);
            current_metadata.push('\n');
        }
    }

    if !current_metadata.is_empty() {
        packages.push(parse_metadata(&current_metadata));
    }

    packages
}

fn check_dependencies(
    registry: &Registry,
    package: &PackageMetadata,
) -> HashSet<PackageWithSource> {
    let mut depends = HashSet::new();
    let packages = registry
        .main
        .iter()
        .chain(registry.community.iter())
        .chain(registry.testing.iter());

    for pkg in packages {
        let provides: Vec<&str> = pkg
            .provides
            .iter()
            .map(|provide| provide.split('=').next().unwrap_or(provide).trim())
            .collect();

        for dep in &package.depends {
            if provides.contains(&dep.as_str()) {
                let source = if registry.main.iter().any(|p| p.package == pkg.package) {
                    "main"
                } else if registry.community.iter().any(|p| p.package == pkg.package) {
                    "community"
                } else {
                    "testing"
                };

                depends.insert(PackageWithSource {
                    package: pkg.clone(),
                    source: source.to_owned(),
                });
            }
        }
    }
    depends
}

async fn download_package(package: &PackageMetadata, main_name: &str, source: &str) {
    let full_name = format!("{}-{}.apk", package.package, package.version);
    let file = format!("dl/{full_name}");
    let exists = fs::metadata(&file);
    if exists.is_err() {
        println!("Downloading {}", package.package);
        let url = format!("{}/{}/{}/{}", BASE_URL, source, ARCH, &full_name);

        let response = reqwest::get(url).await;
        let Ok(response) = response else {
            eprintln!("Error downloading {}", package.package);
            return;
        };
        if !response.status().is_success() {
            eprintln!("Error downloading {}", package.package);
            return;
        }

        let content = response.bytes().await.unwrap();
        fs::write(&file, content).unwrap();
    }

    extract_file(main_name, &file);
}

fn extract_file(main_name: &str, uf: &str) {
    let file = File::open(uf).unwrap();
    let decoder = MultiGzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    let output_dir = format!("bin/{main_name}");
    fs::create_dir_all(&output_dir).unwrap();
    archive.unpack(format!("bin/{main_name}")).unwrap();
}

#[async_recursion]
async fn download_with_dependencies(
    registry: &Registry,
    package_name: &str,
    downloaded: &mut HashSet<String>,
    main: &str,
) {
    if downloaded.contains(package_name) {
        return;
    }
    let package = registry
        .main
        .iter()
        .map(|pkg| (pkg, "main"))
        .chain(registry.community.iter().map(|pkg| (pkg, "community")))
        .chain(registry.testing.iter().map(|pkg| (pkg, "testing")))
        .find(|(pkg, _)| pkg.package == package_name);

    if let Some((package, source)) = package {
        downloaded.insert(package_name.to_owned());

        let depends = check_dependencies(registry, package);
        for depend in depends {
            download_with_dependencies(registry, &depend.package.package, downloaded, main).await;
        }
        download_package(package, main, source).await;
    }
}

fn patch_elfs(package_name: &str) -> std::io::Result<()> {
    let usr_dir = format!("bin/{package_name}/usr");
    let interpreter = format!("{package_name}-tmp/lib/libc.musl-x86_64.so.1");

    for entry in WalkDir::new(&usr_dir) {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            // Check if the file is an ELF binary
            let output = Command::new("file")
                .arg(path)
                .output()
                .expect("Failed to execute file command");

            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.contains("ELF") {
                println!("Patching {}", path.display());

                // Change the interpreter
                Command::new("patchelf")
                    .arg("--set-interpreter")
                    .arg(interpreter.clone())
                    .arg(path)
                    .status()
                    .expect("Failed to set interpreter");

                Command::new("patchelf")
                    .arg("--set-rpath")
                    .arg(format!("{package_name}-tmp/usr/lib"))
                    .arg(path)
                    .status()
                    .expect("Failed to set RPATH");

                println!("{} patched successfully", path.display(),);
            }
        }
    }
    Ok(())
}

fn copy_dir(src: &Path, dest: &Path) -> io::Result<()> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let target_path = dest.join(path.file_name().unwrap());

        if path.is_dir() {
            fs::create_dir_all(&target_path)?;
            copy_dir(&path, &target_path)?;
        } else {
            fs::copy(&path, &target_path)?;
        }
    }
    Ok(())
}

async fn create_package(package_name: &str, bin: &str) -> io::Result<()> {
    let bin_dir = format!("bin/{package_name}");
    let temp_dir = format!("{package_name}-tmp");
    fs::create_dir_all(&temp_dir).unwrap();

    copy_dir(&PathBuf::from(&bin_dir), &PathBuf::from(&temp_dir))?;

    let script = format!(
        "#!/bin/sh\n\
        # Self-extracting script\n\
        TEMP_DIR=\"{0}\"\n\
        cleanup() {{\n\
            rm -rf \"$TEMP_DIR\"\n\
        }}\n\
        trap cleanup EXIT\n\
        tail -n +12 \"$0\" | tar -x --zstd 2>/dev/null\n\
        \"$TEMP_DIR/usr/bin/{1}\"\n\
        exit\n\
        # End of script\n",
        temp_dir, bin
    );

    let tar_file_path = format!("{package_name}.tar.gz");
    {
        let tar_file = File::create(&tar_file_path)?;
        // FIXME: this appears to be working but is missing some data at end
        let encoder = Encoder::new(&tar_file, 15)?;
        let mut builder = Builder::new(encoder);
        builder.append_dir_all(&temp_dir, &temp_dir)?;
        builder.finish()?;
    }

    let mut tar = File::open(&tar_file_path)?;
    let mut buffer = Vec::new();
    tar.read_to_end(&mut buffer)?;

    let mut exec_file = File::create(bin)?;
    let mut combined = Vec::new();
    combined.extend_from_slice(script.as_bytes());
    combined.extend_from_slice(&buffer);
    exec_file.write_all(&combined)?;
    fs::set_permissions(bin, Permissions::from_mode(0o755))?;

    fs::remove_dir_all(temp_dir)?;
    fs::remove_file(tar_file_path)?;
    fs::remove_dir_all(&bin_dir)?;

    Ok(())
}

async fn check_and_download_metadata(
    path: &str,
    url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let tar_path = format!("{}.tar.gz", path);
    let local_size = if Path::new(&tar_path).exists() {
        Some(fs::metadata(&tar_path)?.len())
    } else {
        None
    };

    let client = Client::new();
    let response = client.head(url).send().await?;

    if response.status().is_success() {
        let remote_size = response.content_length();

        if let Some(local_size) = local_size {
            if Some(local_size) == remote_size && PathBuf::from(path).exists() {
                return Ok(());
            } else {
                println!("{} is outdated. Downloading...", path);
            }
        } else {
            println!("{} not found. Downloading...", path);
        }

        let remote_bytes = client.get(url).send().await?.bytes().await?;
        fs::write(&tar_path, &remote_bytes)?;

        let tar = File::open(&tar_path)?;
        let decoder = MultiGzDecoder::new(tar);
        let mut archive = Archive::new(decoder);

        let temp_extract_path = PathBuf::from("temp_extract");
        fs::create_dir_all(&temp_extract_path)?;

        archive.unpack(&temp_extract_path)?;

        let apkindex_path = temp_extract_path.join("APKINDEX");

        if apkindex_path.exists() {
            fs::rename(apkindex_path, path)?;
        }

        fs::remove_dir_all(temp_extract_path)?;
    } else {
        eprintln!(
            "Failed to retrieve metadata for {}: {}",
            url,
            response.status()
        );
        return Err("Failed to retrieve remote file size".into());
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let main_path = "index/MAIN";
    let community_path = "index/COMMUNITY";
    let testing_path = "index/TESTING";

    fs::create_dir_all("dl").unwrap();
    fs::create_dir_all("index").unwrap();

    check_and_download_metadata(
        main_path,
        &format!("{BASE_URL}/main/x86_64/APKINDEX.tar.gz"),
    )
    .await
    .unwrap();
    check_and_download_metadata(
        community_path,
        &format!("{BASE_URL}/community/x86_64/APKINDEX.tar.gz"),
    )
    .await
    .unwrap();
    check_and_download_metadata(
        testing_path,
        &format!("{BASE_URL}/testing/x86_64/APKINDEX.tar.gz"),
    )
    .await
    .unwrap();

    let main = fs::read_to_string("index/MAIN").unwrap();
    let community = fs::read_to_string("index/COMMUNITY").unwrap();
    let testing = fs::read_to_string("index/TESTING").unwrap();

    let main = full_metadata(&main);
    let community = full_metadata(&community);
    let testing = full_metadata(&testing);

    let registry = Registry {
        main,
        community,
        testing,
    };

    match args.command {
        cli::Commands::Generate { packages } => {
            let mut downloaded = HashSet::new();
            for package_name in packages {
                download_with_dependencies(
                    &registry,
                    &package_name,
                    &mut downloaded,
                    &package_name,
                )
                .await;

                if let Err(e) = patch_elfs(&package_name) {
                    eprintln!("Error: {}", e);
                }

                let package = registry
                    .main
                    .iter()
                    .chain(registry.community.iter())
                    .chain(registry.testing.iter())
                    .find(|pkg| pkg.package == package_name);

                if let Some(package) = package {
                    let bin = package
                        .provides
                        .iter()
                        .map(|provide| provide.split('=').next().unwrap_or(provide).trim())
                        .find(|p| p.starts_with("cmd:"))
                        .map(|p| p.trim_start_matches("cmd:"));

                    if let Some(bin) = bin {
                        create_package(&package_name, bin).await.unwrap();
                    } else {
                        println!("The package doesn't provide a binary");
                    }
                }
            }
        }
    }
}
