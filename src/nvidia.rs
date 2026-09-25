//! NVIDIA 上游调用 (chat/completions + models)。

use crate::config::Config;
use std::time::Duration;

pub struct Upstream {
    pub base_url: String,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
}

impl Upstream {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            base_url: cfg.nvidia_base_url.trim_end_matches('/').to_string(),
            connect_timeout: Duration::from_secs(cfg.upstream_connect_timeout_secs),
            read_timeout: Duration::from_secs(cfg.upstream_read_timeout_secs),
        }
    }

    fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .connect_timeout(self.connect_timeout)
            .timeout(self.read_timeout)
            .build()
            .unwrap_or_default()
    }

    /// 非流式 chat completions。返回 (status, body)。
    pub async fn chat(&self, api_key: &str, body: &serde_json::Value) -> (u16, serde_json::Value) {
        let url = format!("{}/chat/completions", self.base_url);
        let resp = self
            .client()
            .post(&url)
            .bearer_auth(api_key)
            .json(body)
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                let data = r.json::<serde_json::Value>().await.unwrap_or(serde_json::json!({}));
                (status, data)
            }
            Err(e) => (0, serde_json::json!({"error": {"message": e.to_string()}})),
        }
    }

    /// 开启流式连接。返回 (status, response)。status==200 时 response 可逐行读 SSE。
    pub async fn chat_stream(
        &self,
        api_key: &str,
        body: &serde_json::Value,
    ) -> Result<(u16, reqwest::Response), String> {
        let url = format!("{}/chat/completions", self.base_url);
        let resp = self
            .client()
            .post(&url)
            .bearer_auth(api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        Ok((status, resp))
    }

    /// 拉取模型列表。
    pub async fn list_models(&self, api_key: &str) -> (u16, Vec<String>) {
        let url = format!("{}/models", self.base_url);
        let resp = self.client().get(&url).bearer_auth(api_key).send().await;
        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                let data: serde_json::Value = r.json().await.unwrap_or(serde_json::json!({}));
                let ids = data["data"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|m| m["id"].as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                (status, ids)
            }
            Err(_) => (0, vec![]),
        }
    }
}
