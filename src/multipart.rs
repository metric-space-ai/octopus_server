#[cfg(test)]
pub mod tests {
    use crate::Result;
    use std::{collections::HashMap, fs::File, io::Read};

    pub const BOUNDARY: &str = "------------------------0123456789abcdef";

    pub fn file_data(
        content_type: &str,
        name: &str,
        path: &str,
        end_boundary: bool,
    ) -> Result<String> {
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

        if end_boundary {
            data.push_str(&format!("--{BOUNDARY}--\r\n"));
        }

        Ok(data)
    }

    pub fn text_field_data(body: &str, fields: HashMap<&str, &str>, end_boundary: bool) -> String {
        let mut data = body.to_string();

        for (key, value) in fields {
            data.push_str(&format!("--{BOUNDARY}\r\n"));
            data.push_str(&format!(
                "Content-Disposition: form-data; name=\"{key}\"\r\n"
            ));
            data.push_str("\r\n");

            data.push_str(value);

            data.push_str("\r\n");
        }

        if end_boundary {
            data.push_str(&format!("--{BOUNDARY}--\r\n"));
        }

        data
    }
}
