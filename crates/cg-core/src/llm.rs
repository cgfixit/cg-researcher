//! Model backends. One OpenAI-compatible client covers every local server
//! upstream could not use: Ollama (`/v1`), LM Studio, llama.cpp `llama-server`,
//! MLX (`mlx_lm.server`), vLLM and LocalAI. The triple-gated external
//! fallback (Anthropic / xAI) lives in `external.rs`.

use std::time::Duration;

use serde_json::{Value, json};

use crate::egress::{Egress, is_loopback_url};

#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone, Default)]
pub struct ChatReply {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub model: String,
}

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error(transparent)]
    Egress(#[from] crate::egress::EgressError),
    #[error("model server: {0}")]
    Http(String),
    #[error("model server returned an unreadable reply")]
    Shape,
}

#[derive(Clone)]
pub struct OpenAiCompat {
    base: String,
    egress: Egress,
    key: Option<crate::secrets::Secret>,
    pub label: &'static str,
}

impl OpenAiCompat {
    /// A local server. Loopback HTTP is allowed; a non-loopback host is pinned
    /// exactly and must be HTTPS.
    pub fn local(
        base_url: &str,
        timeout: Duration,
        key: Option<crate::secrets::Secret>,
    ) -> anyhow::Result<Self> {
        let url = url::Url::parse(base_url)?;
        let host = url.host_str().unwrap_or_default().to_string();
        let hosts: Vec<&str> = if is_loopback_url(&url) {
            vec![]
        } else {
            vec![host.as_str()]
        };
        let egress = Egress::new("llm-local", &hosts, true, timeout)?;
        egress.check(&url)?;
        Ok(Self {
            base: base_url.trim_end_matches('/').into(),
            egress,
            key,
            label: "local",
        })
    }

    pub(crate) fn egress(&self) -> &Egress {
        &self.egress
    }

    /// Model ids the local server reports (`GET /models`).
    pub async fn list_models(&self) -> Result<Vec<String>, LlmError> {
        let rb = self.auth(self.egress.get(&format!("{}/models", self.base))?);
        let resp = rb
            .send()
            .await
            .map_err(|e| LlmError::Http(crate::sanitizer::redact(&e.to_string())))?;
        if !resp.status().is_success() {
            return Err(LlmError::Http(resp.status().to_string()));
        }
        let v: Value = resp.json().await.map_err(|_| LlmError::Shape)?;
        let mut ids: Vec<String> = v["data"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|m| m["id"].as_str().map(str::to_string))
            .collect();
        ids.sort();
        Ok(ids)
    }

    fn auth(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.key {
            Some(k) => rb.bearer_auth(k.expose()),
            None => rb,
        }
    }

    pub async fn chat(
        &self,
        model: &str,
        messages: &[Value],
        tools: &[Value],
        max_tokens: u32,
        temperature: f32,
    ) -> Result<ChatReply, LlmError> {
        let mut body = json!({
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": false,
        });
        if !tools.is_empty() {
            body["tools"] = Value::Array(tools.to_vec());
        }
        let rb = self.auth(
            self.egress
                .post(&format!("{}/chat/completions", self.base))?,
        );
        let resp = rb
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::Http(crate::sanitizer::redact(&e.to_string())))?;
        let status = resp.status();
        let v: Value = resp.json().await.map_err(|_| LlmError::Shape)?;
        if !status.is_success() {
            let msg = v["error"]["message"]
                .as_str()
                .or(v["error"].as_str())
                .unwrap_or("request failed");
            return Err(LlmError::Http(format!(
                "{status}: {}",
                crate::sanitizer::redact(msg)
            )));
        }
        parse_chat(&v)
    }

    pub async fn embed(&self, model: &str, inputs: &[String]) -> Result<Vec<Vec<f32>>, LlmError> {
        let rb = self.auth(self.egress.post(&format!("{}/embeddings", self.base))?);
        let resp = rb
            .json(&json!({"model": model, "input": inputs}))
            .send()
            .await
            .map_err(|e| LlmError::Http(crate::sanitizer::redact(&e.to_string())))?;
        if !resp.status().is_success() {
            return Err(LlmError::Http(resp.status().to_string()));
        }
        let v: Value = resp.json().await.map_err(|_| LlmError::Shape)?;
        let mut out = Vec::new();
        for item in v["data"].as_array().ok_or(LlmError::Shape)? {
            let emb = item["embedding"].as_array().ok_or(LlmError::Shape)?;
            out.push(
                emb.iter()
                    .map(|x| x.as_f64().unwrap_or(0.0) as f32)
                    .collect(),
            );
        }
        if out.len() != inputs.len() {
            return Err(LlmError::Shape);
        }
        Ok(out)
    }

    pub async fn health(&self) -> bool {
        match self.egress.get(&format!("{}/models", self.base)) {
            Ok(rb) => self
                .auth(rb)
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false),
            Err(_) => false,
        }
    }
}

/// Remove `<think>…</think>` blocks some local reasoning models emit inline.
pub fn strip_thinking(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("<think>") {
        out.push_str(&rest[..start]);
        match rest[start..].find("</think>") {
            Some(end) => rest = &rest[start + end + "</think>".len()..],
            None => {
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out.trim().to_string()
}

pub fn parse_chat(v: &Value) -> Result<ChatReply, LlmError> {
    let msg = &v["choices"][0]["message"];
    if msg.is_null() {
        return Err(LlmError::Shape);
    }
    let content = strip_thinking(msg["content"].as_str().unwrap_or(""));
    let mut tool_calls = Vec::new();
    if let Some(calls) = msg["tool_calls"].as_array() {
        for (i, c) in calls.iter().enumerate() {
            let name = c["function"]["name"].as_str().unwrap_or("").to_string();
            let arguments = match &c["function"]["arguments"] {
                Value::String(s) => s.clone(),
                Value::Null => "{}".into(),
                other => other.to_string(),
            };
            let id = c["id"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| format!("call_{i}"));
            tool_calls.push(ToolCall {
                id,
                name,
                arguments,
            });
        }
    }
    Ok(ChatReply {
        content,
        tool_calls,
        model: v["model"].as_str().unwrap_or("").into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tool_calls_with_string_or_object_args() {
        let v = json!({"model":"m","choices":[{"message":{"content":"<think>x</think>hi","tool_calls":[
            {"id":"a","function":{"name":"web_search","arguments":"{\"query\":\"q\"}"}},
            {"function":{"name":"calendar_list","arguments":{"days":1}}}]}}]});
        let r = parse_chat(&v).expect("parse");
        assert_eq!(r.content, "hi");
        assert_eq!(r.tool_calls.len(), 2);
        assert_eq!(r.tool_calls[1].id, "call_1");
        assert_eq!(r.tool_calls[1].arguments, "{\"days\":1}");
    }

    #[test]
    fn local_client_refuses_plain_http_to_lan() {
        assert!(
            OpenAiCompat::local("http://192.168.1.10:1234/v1", Duration::from_secs(1), None)
                .is_err()
        );
        assert!(
            OpenAiCompat::local("http://127.0.0.1:1234/v1", Duration::from_secs(1), None).is_ok()
        );
        assert!(
            OpenAiCompat::local("https://gpu-box.lan/v1", Duration::from_secs(1), None).is_ok()
        );
    }
}
