use crate::{context::Context, Result};
use fantoccini::ClientBuilder;
use std::sync::Arc;

pub async fn scraper(context: Arc<Context>, url: &str) -> Result<String> {
    if let Some(web_driver_url) = context.get_config().await?.web_driver_url {
        let client = ClientBuilder::native().connect(&web_driver_url).await?;

        client.goto(url).await?;

        let source = client.source().await?;

        client.close().await?;

        return Ok(source);
    }

    Ok(String::new())
}
