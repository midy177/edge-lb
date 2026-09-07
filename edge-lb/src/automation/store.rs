use anyhow::{Context, Result};

use super::model::{AutomationConfig, AutomationTemplate};
use crate::config::Config;

pub fn load(_cfg: &Config) -> Result<AutomationConfig> {
    let repository = crate::storage::repository()?;
    if let Some(payload) = repository.get("automation", "config")? {
        return serde_json::from_str(&payload).context("parsing stored automation config");
    }
    Ok(AutomationConfig::default())
}

pub fn save(_cfg: &Config, value: &AutomationConfig) -> Result<()> {
    let payload = serde_json::to_string(value).context("encoding automation config")?;
    crate::storage::repository()?.put(
        "automation",
        "config",
        crate::storage::next_revision(),
        payload,
    )
}

pub fn upsert_template(
    mut config: AutomationConfig,
    old_name: Option<&str>,
    template: AutomationTemplate,
) -> (AutomationConfig, AutomationTemplate) {
    let key = old_name.unwrap_or(&template.name);
    match config.templates.iter_mut().find(|item| item.name == key) {
        Some(existing) => *existing = template.clone(),
        None => config.templates.push(template.clone()),
    }
    (config, template)
}

pub fn delete_template(mut config: AutomationConfig, name: &str) -> (AutomationConfig, bool) {
    let before = config.templates.len();
    config.templates.retain(|item| item.name != name);
    let changed = before != config.templates.len();
    (config, changed)
}

pub fn template(cfg: &Config, name: &str) -> Result<Option<AutomationTemplate>> {
    Ok(load(cfg)?
        .templates
        .into_iter()
        .find(|item| item.name == name))
}
