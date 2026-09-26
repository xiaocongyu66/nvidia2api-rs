//! 临时邮箱服务商 (对齐原版 email_providers.py): cloudflare_temp_email / duckmail。全异步。

use serde_json::Value;

pub struct Inbox {
    pub address: String,
    pub token: String,
}

fn http() -> reqwest::Client {
    reqwest::Client::new()
}

/// 提取 6 位验证码 (对齐原版 _extract_verification_code)。
pub fn extract_code(raw: &str) -> Option<String> {
    let clean = raw.replace("=\r\n", "").replace("=\n", "");
    let lower = clean.to_lowercase();
    if let Some(idx) = lower.find("verification code") {
        let snippet = &clean[idx..(idx + 500).min(clean.len())];
        if let Some(c) = regex_pair(snippet) {
            return Some(c);
        }
    }
    regex_pair(&clean)
}

fn regex_pair(s: &str) -> Option<String> {
    // 对齐 (\d{3})\s*[-–]\s*(\d{3}) + 前后非数字 lookaround:
    // 先剥掉全部空白, 再扫 ddd-ddd (允许 - 或 –)
    let stripped: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let b: Vec<char> = stripped.chars().collect();
    let n = b.len();
    if n < 7 {
        return None;
    }
    for i in 0..=(n - 7) {
        if b[i].is_ascii_digit()
            && b[i + 1].is_ascii_digit()
            && b[i + 2].is_ascii_digit()
            && (b[i + 3] == '-' || b[i + 3] == '\u{2013}')
            && b[i + 4].is_ascii_digit()
            && b[i + 5].is_ascii_digit()
            && b[i + 6].is_ascii_digit()
        {
            let before_ok = i == 0 || !b[i - 1].is_ascii_digit();
            let after_ok = i + 7 >= n || !b[i + 7].is_ascii_digit();
            if before_ok && after_ok {
                let a: String = b[i..i + 3].iter().collect();
                let c: String = b[i + 4..i + 7].iter().collect();
                return Some(format!("{a}{c}"));
            }
        }
    }
    None
}

async fn get_json(client: &reqwest::Client, url: &str, token: &str) -> Option<Value> {
    client
        .get(url)
        .bearer_auth(token)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .ok()?
        .json::<Value>()
        .await
        .ok()
}

/// cloudflare_temp_email 自部署。
pub struct CloudflareTempEmail {
    pub api_url: String,
    pub admin_auth: String,
    pub domain: String,
}

impl CloudflareTempEmail {
    pub async fn create_inbox(&self, name: &str) -> Result<Inbox, String> {
        let url = format!("{}/admin/new_address", self.api_url);
        let resp = http()
            .post(&url)
            .header("x-admin-auth", &self.admin_auth)
            .json(&serde_json::json!({"name": name, "domain": self.domain, "enablePrefix": false}))
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let data: Value = resp.json().await.map_err(|e| e.to_string())?;
        // 不同 moemail 版本响应字段: address | email
        let address = data["address"].as_str().or_else(|| data["email"].as_str()).unwrap_or("").to_string();
        let token = data["jwt"].as_str().unwrap_or("").to_string();
        if address.is_empty() || token.is_empty() {
            return Err(format!("email create failed: {data}"));
        }
        Ok(Inbox { address, token })
    }

    pub async fn poll_code(&self, inbox: &Inbox, timeout_secs: u64) -> Option<String> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        let client = http();
        while tokio::time::Instant::now() < deadline {
            if let Some(data) = get_json(&client, &format!("{}/api/mails?limit=5&offset=0", self.api_url), &inbox.token).await {
                let mails = data["results"].as_array().cloned().unwrap_or_else(|| data["data"].as_array().cloned().unwrap_or_default());
                for mail in mails {
                    let id = mail["id"].as_str().map(String::from).or_else(|| mail["_id"].as_str().map(String::from));
                    let Some(id) = id else { continue };
                    if let Some(d) = get_json(&client, &format!("{}/api/mail/{id}", self.api_url), &inbox.token).await {
                        let raw = d["raw"].as_str().unwrap_or("");
                        if let Some(code) = extract_code(raw) {
                            return Some(code);
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        None
    }
}

/// DuckMail。
pub struct DuckMail {
    pub api_url: String,
    pub domain: String,
    pub api_key: String,
}

impl DuckMail {
    pub async fn create_inbox(&self, name: &str) -> Result<Inbox, String> {
        let address = format!("{name}@{}", self.domain);
        let password = format!("dm_{}", crate::register::rand_hex(8));
        let client = http();
        client
            .post(format!("{}/accounts", self.api_url))
            .header("x-api-key", &self.api_key)
            .json(&serde_json::json!({"address": address, "password": password}))
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?;
        let data: Value = client
            .post(format!("{}/token", self.api_url))
            .json(&serde_json::json!({"address": address, "password": password}))
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        let token = data["token"].as_str().unwrap_or("").to_string();
        if token.is_empty() {
            return Err(format!("duckmail token failed: {data}"));
        }
        Ok(Inbox { address, token })
    }

    pub async fn poll_code(&self, inbox: &Inbox, timeout_secs: u64) -> Option<String> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        let client = http();
        while tokio::time::Instant::now() < deadline {
            if let Some(data) = get_json(&client, &format!("{}/messages?page=1", self.api_url), &inbox.token).await {
                for msg in data["hydra:member"].as_array().cloned().unwrap_or_default() {
                    let id = msg["id"].as_i64().map(|v| v.to_string()).or_else(|| msg["id"].as_str().map(String::from));
                    let Some(id) = id else { continue };
                    if let Some(d) = get_json(&client, &format!("{}/messages/{id}", self.api_url), &inbox.token).await {
                        let mut body = d["text"].as_str().unwrap_or("").to_string();
                        if let Some(html) = d["html"].as_array() {
                            for h in html {
                                if let Some(s) = h.as_str() {
                                    body.push_str(s);
                                }
                            }
                        } else if let Some(s) = d["html"].as_str() {
                            body.push_str(s);
                        }
                        if let Some(code) = extract_code(&body) {
                            return Some(code);
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_extraction() {
        assert_eq!(extract_code("Your verification code is 123-456."), Some("123456".into()));
        assert_eq!(extract_code("code 987–656 end"), Some("987656".into()));
        assert_eq!(extract_code("code 123 - 456 ok"), Some("123456".into()));
        assert_eq!(extract_code("no digits here"), None);
        // 前后是数字的串不算 (对齐 lookaround)
        assert_eq!(extract_code("1123-4567"), None);
    }
}

/// MoeMail (beilunyang/moemail — Cloudflare Workers 临时邮箱)。
pub struct MoeMail {
    pub api_url: String, // 部署基址, 如 https://xxx.pages.dev
    pub api_key: String, // X-API-Key
    pub domain: String,
}

impl MoeMail {
    pub async fn create_inbox(&self, name: &str) -> Result<Inbox, String> {
        let resp = http()
            .post(format!("{}/api/emails/generate", self.api_url))
            .header("X-API-Key", &self.api_key)
            .json(&serde_json::json!({"name": name, "expiryTime": 0, "domain": self.domain}))
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let data: Value = resp.json().await.map_err(|e| e.to_string())?;
        if status >= 400 {
            return Err(format!("moemail generate failed ({status}): {data}"));
        }
        // 不同 moemail 版本响应字段: address | email
        let address = data["address"].as_str().or_else(|| data["email"].as_str()).unwrap_or("").to_string();
        let email_id = data["id"].as_str().map(String::from).or_else(|| data["id"].as_i64().map(|v| v.to_string())).unwrap_or_default();
        if address.is_empty() || email_id.is_empty() {
            return Err(format!("moemail generate failed: {data}"));
        }
        Ok(Inbox { address, token: email_id })
    }

    pub async fn poll_code(&self, inbox: &Inbox, timeout_secs: u64) -> Option<String> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        let client = http();
        while tokio::time::Instant::now() < deadline {
            let url = format!("{}/api/emails/{}", self.api_url, inbox.token);
            if let Ok(resp) = client
                .get(&url)
                .header("X-API-Key", &self.api_key)
                .timeout(std::time::Duration::from_secs(15))
                .send()
                .await
            {
                if let Ok(data) = resp.json::<Value>().await {
                    let messages = data["messages"].as_array().cloned()
                        .or_else(|| data["data"].as_array().cloned())
                        .unwrap_or_default();
                    for msg in messages {
                        let mid = msg["id"].as_str().map(String::from)
                            .or_else(|| msg["id"].as_i64().map(|v| v.to_string()));
                        let Some(mid) = mid else { continue };
                        let detail_url = format!("{}/api/emails/{}/{}", self.api_url, inbox.token, mid);
                        if let Ok(d) = client
                            .get(&detail_url)
                            .header("X-API-Key", &self.api_key)
                            .timeout(std::time::Duration::from_secs(15))
                            .send()
                            .await
                        {
                            if let Ok(d) = d.json::<Value>().await {
                                let m = &d["message"];
                                let mut body = m["html"].as_str().unwrap_or("").to_string();
                                body.push_str(m["content"].as_str().unwrap_or(""));
                                if let Some(code) = extract_code(&body) {
                                    return Some(code);
                                }
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        None
    }
}
