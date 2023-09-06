use crate::{error::AppError, Result};
use bytesize::MIB;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
//use std::process::Command;
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

pub async fn get() -> Result<ServerResources> {
    let cpus = num_cpus::get();
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
    /*
        let nvidia_smi_list = Command::new("nvidia-smi").arg("--list-gpus").output()?;
        let nvidia_smi_list = String::from_utf8(nvidia_smi_list.stdout.to_vec())?;
    */
    let nvidia_smi_list =
        r#"GPU 0: NVIDIA RTX A4500 (UUID: GPU-174d612c-3b65-e9ab-a103-79738578fcc4)
GPU 1: NVIDIA RTX A4500 (UUID: GPU-47374b93-b852-0058-b0d0-6ff852fdc0fe)
GPU 2: NVIDIA RTX A4500 (UUID: GPU-048c170b-515e-a61a-c196-01d72b7c9b20)"#
            .to_string();

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
                /*
                                let nvidia_smi_memory_total = Command::new("nvidia-smi")
                                    .arg("--query-gpu=memory.total")
                                    .arg("--format=csv,nounits,noheader")
                                    .arg(format!("--id={}", id))
                                    .output()?;
                                let nvidia_smi_memory_total =
                                    String::from_utf8(nvidia_smi_memory_total.stdout.to_vec())?;
                                let nvidia_smi_memory_free = Command::new("nvidia-smi")
                                    .arg("--query-gpu=memory.free")
                                    .arg("--format=csv,nounits,noheader")
                                    .arg(format!("--id={}", id))
                                    .output()?;
                                let nvidia_smi_memory_free =
                                    String::from_utf8(nvidia_smi_memory_free.stdout.to_vec())?;
                */
                let nvidia_smi_memory_total = r#"20470"#.to_string();
                let nvidia_smi_memory_free = r#"5991"#.to_string();

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
        device_map.insert(format!("cuda:{i}"), gpu.memory_total.clone());
    }

    device_map.insert("cpu".to_string(), memory_total.clone());

    let server_resources = ServerResources {
        cpus,
        device_map,
        gpus,
        memory_free,
        memory_total,
        memory_used,
        physical_cpus,
    };

    Ok(server_resources)
}
