#[cfg(test)]
pub mod tests {
    use crate::Result;
    use std::{fs::File, io::Read};

    pub const BOUNDARY: &str = "------------------------0123456789abcdef";

    pub async fn file_data(content_type: &str, name: &str, path: &str) -> Result<String> {
        let mut data = String::new();
        let mut file_data = vec![];
        data.push_str(&format!("--{BOUNDARY}\r\n"));
        data.push_str(&format!(
            "Content-Disposition: form-data; name=\"smfile\"; filename=\"{name}\"\r\n"
        ));
        data.push_str(&format!("Content-Type: {content_type}\r\n"));
        data.push_str("\r\n");

        let mut f = File::open(path)?;
        f.read_to_end(&mut file_data)?;

        data.push_str(&String::from_utf8_lossy(&file_data));

        data.push_str("\r\n");
        data.push_str(&format!("--{BOUNDARY}--\r\n"));

        Ok(data)
    }
}
