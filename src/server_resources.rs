use crate::{error::AppError, Result};
use bytesize::MIB;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, process::Command};
use systemstat::{saturating_sub_bytes, ByteSize, Platform, System};
use utoipa::ToSchema;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct Gpu {
    pub id: String,
    pub memory_free: String,
    pub memory_total: String,
    pub memory_used: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct ServerResources {
    pub cpus: usize,
    pub device_map: HashMap<String, String>,
    pub gpus: Vec<Gpu>,
    pub memory_free: String,
    pub memory_total: String,
    pub memory_used: String,
    pub physical_cpus: usize,
}

pub fn get() -> Result<ServerResources> {
    let logical_cpus = num_cpus::get();
    let mut gpus = vec![];
    let mut memory_free = String::new();
    let mut memory_total = String::new();
    let mut memory_used = String::new();
    let physical_cpus = num_cpus::get_physical();
    let sys = System::new();

    if let Ok(memory) = sys.memory() {
        memory_total = memory.total.to_string_as(true).replace(' ', "");
        memory_free = memory.free.to_string_as(true).replace(' ', "");
        memory_used = saturating_sub_bytes(memory.total, memory.free)
            .to_string_as(true)
            .replace(' ', "");
    }
    let nvidia_smi_list = Command::new("nvidia-smi").arg("--list-gpus").output();
    let nvidia_smi_list = match nvidia_smi_list {
        Err(_) => String::new(),
        Ok(nvidia_smi_list) => String::from_utf8(nvidia_smi_list.stdout.clone())?,
    };
    /*
            let nvidia_smi_list =
                r#"GPU 0: Tesla T4 (UUID: GPU-d0da269e-9437-3293-6816-e4d91bb0be32)
    GPU 1: Tesla T4 (UUID: GPU-f8b923b3-4843-f15a-89ab-bec1cde0935d)
    GPU 2: Tesla T4 (UUID: GPU-6b1bbbc2-9afe-ca0f-101e-4663159db831)
    GPU 3: Tesla T4 (UUID: GPU-b0868300-4848-d1e3-8c55-7054206bdddd)
    "#
                    .to_string();
    */
    if nvidia_smi_list.starts_with("GPU") {
        for line in nvidia_smi_list.lines() {
            let mut name = String::new();
            let mut id = String::new();
            for line in line.to_string().split('(') {
                if line.starts_with("GPU") {
                    name = line
                        .to_string()
                        .strip_suffix(' ')
                        .ok_or(AppError::Parsing)?
                        .to_string();
                }
                if line.starts_with("UUID") {
                    id = line
                        .strip_prefix("UUID: ")
                        .ok_or(AppError::Parsing)?
                        .to_string()
                        .strip_suffix(')')
                        .ok_or(AppError::Parsing)?
                        .to_string();
                }
            }

            if !id.is_empty() {
                let nvidia_smi_memory_total = Command::new("nvidia-smi")
                    .arg("--query-gpu=memory.total")
                    .arg("--format=csv,nounits,noheader")
                    .arg(format!("--id={id}"))
                    .output()?;
                let nvidia_smi_memory_total =
                    String::from_utf8(nvidia_smi_memory_total.stdout.clone())?
                        .strip_suffix('\n')
                        .ok_or(AppError::Parsing)?
                        .to_string();
                let nvidia_smi_memory_free = Command::new("nvidia-smi")
                    .arg("--query-gpu=memory.free")
                    .arg("--format=csv,nounits,noheader")
                    .arg(format!("--id={id}"))
                    .output()?;
                let nvidia_smi_memory_free =
                    String::from_utf8(nvidia_smi_memory_free.stdout.clone())?
                        .strip_suffix('\n')
                        .ok_or(AppError::Parsing)?
                        .to_string();

                //let nvidia_smi_memory_total = r#"15360"#.to_string();
                //let nvidia_smi_memory_free = r#"14925"#.to_string();

                let nvidia_smi_memory_total = nvidia_smi_memory_total.parse::<u64>()? * MIB;
                let nvidia_smi_memory_free = nvidia_smi_memory_free.parse::<u64>()? * MIB;
                let nvidia_smi_memory_used = nvidia_smi_memory_total - nvidia_smi_memory_free;

                let nvidia_smi_memory_total = ByteSize(nvidia_smi_memory_total);
                let nvidia_smi_memory_free = ByteSize(nvidia_smi_memory_free);
                let nvidia_smi_memory_used = ByteSize(nvidia_smi_memory_used);

                let gpu = Gpu {
                    id,
                    memory_free: nvidia_smi_memory_free.to_string_as(true).replace(' ', ""),
                    memory_total: nvidia_smi_memory_total.to_string_as(true).replace(' ', ""),
                    memory_used: nvidia_smi_memory_used.to_string_as(true).replace(' ', ""),
                    name,
                };

                gpus.push(gpu);
            }
        }
    }

    let mut device_map = HashMap::new();

    for (i, gpu) in gpus.iter().enumerate() {
        device_map.insert(format!("cuda:{i}"), gpu.memory_free.clone());
    }

    device_map.insert("cpu".to_string(), memory_free.clone());

    let server_resources = ServerResources {
        cpus: logical_cpus,
        device_map,
        gpus,
        memory_free,
        memory_total,
        memory_used,
        physical_cpus,
    };

    Ok(server_resources)
}
