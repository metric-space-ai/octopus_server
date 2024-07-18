use crate::{
    context::Context,
    entity::{WaspGenerator, WaspGeneratorStatus},
    error::AppError,
    get_pwd, Result, WASP_GENERATOR_DIR,
};
use std::{
    fs::{self, create_dir, remove_dir_all, File},
    io::{Read, Seek, Write},
    iter::Iterator,
    path::Path,
    process::Command,
    sync::Arc,
};
use zip::{result::ZipError, write::SimpleFileOptions};

use walkdir::{DirEntry, WalkDir};

pub async fn generate(
    context: Arc<Context>,
    wasp_generator: WaspGenerator,
) -> Result<WaspGenerator> {
    let pwd = get_pwd()?;

    let wasp_generator_id = wasp_generator.id;
    let wasp_generator_dir_path =
        format!("{pwd}/{WASP_GENERATOR_DIR}/generator-{wasp_generator_id}");
    let dir_exists = Path::new(&wasp_generator_dir_path).is_dir();
    if !dir_exists {
        create_dir(&wasp_generator_dir_path)?;
    }

    let mut parameters = String::new();

    let main_llm_openai_api_key = context
        .get_config()
        .await?
        .get_parameter_main_llm_openai_api_key();

    if let Some(main_llm_openai_api_key) = main_llm_openai_api_key {
        parameters.push_str(&format!("OPENAI_API_KEY={main_llm_openai_api_key} "));
    }

    let path = format!("{wasp_generator_dir_path}/{wasp_generator_id}.sh");
    let mut file = File::create(&path)?;
    file.write_fmt(format_args!("#!/bin/bash\n"))?;
    file.write_fmt(format_args!("cd {wasp_generator_dir_path}\n"))?;
    file.write_fmt(format_args!(
        "{parameters} echo \"{}\" | wasp-cli new {} --template ai-generated\n",
        wasp_generator.description, wasp_generator.name
    ))?;

    let command_output = Command::new("/bin/sh").arg(path).output()?;

    let log = String::from_utf8(command_output.stdout)?;

    let dst_file = format!("{wasp_generator_dir_path}/{wasp_generator_id}.zip");
    let src_dir = format!("{wasp_generator_dir_path}/{}", wasp_generator.name);
    create_archive(&src_dir, &dst_file, zip::CompressionMethod::Deflated)?;

    let code = fs::read(dst_file)?;

    let mut transaction = context.octopus_database.transaction_begin().await?;

    let wasp_generator = context
        .octopus_database
        .update_wasp_generator_generated(
            &mut transaction,
            wasp_generator.id,
            &code,
            &log,
            WaspGeneratorStatus::Generated,
        )
        .await?;

    context
        .octopus_database
        .transaction_commit(transaction)
        .await?;

    remove_dir_all(wasp_generator_dir_path)?;

    Ok(wasp_generator)
}

fn zip_dir<T>(
    it: &mut dyn Iterator<Item = DirEntry>,
    prefix: &str,
    writer: T,
    method: zip::CompressionMethod,
) -> Result<()>
where
    T: Write + Seek,
{
    let mut zip = zip::ZipWriter::new(writer);
    let options = SimpleFileOptions::default()
        .compression_method(method)
        .unix_permissions(0o755);

    let prefix = Path::new(prefix);
    let mut buffer = Vec::new();
    for entry in it {
        let path = entry.path();
        let name = path.strip_prefix(prefix)?;
        let path_as_string = name.to_str().map(str::to_owned).ok_or(AppError::NotUtf8)?;

        if path.is_file() {
            zip.start_file(path_as_string, options)?;
            let mut f = File::open(path)?;

            f.read_to_end(&mut buffer)?;
            zip.write_all(&buffer)?;
            buffer.clear();
        } else if !name.as_os_str().is_empty() {
            zip.add_directory(path_as_string, options)?;
        }
    }
    zip.finish()?;

    Ok(())
}

fn create_archive(src_dir: &str, dst_file: &str, method: zip::CompressionMethod) -> Result<()> {
    if !Path::new(src_dir).is_dir() {
        return Err(ZipError::FileNotFound.into());
    }

    let path = Path::new(dst_file);
    let file = File::create(path)?;

    let walkdir = WalkDir::new(src_dir);
    let it = walkdir.into_iter();

    zip_dir(
        &mut it.filter_map(std::result::Result::ok),
        src_dir,
        file,
        method,
    )?;

    Ok(())
}
