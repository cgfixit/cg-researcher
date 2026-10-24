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

    /// `chat` with `stream: true`. Content deltas go to `on_delta` as they
    /// arrive (the caller guards them); the full reply, including streamed
    /// tool calls, is returned at the end. A server that ignores `stream`
    /// and answers with plain JSON is handled the same as `chat`.
    pub async fn chat_stream(
        &self,
        model: &str,
        messages: &[Value],
        tools: &[Value],
        max_tokens: u32,
        temperature: f32,
        on_delta: &mut (dyn FnMut(&str) + Send),
    ) -> Result<ChatReply, LlmError> {
        let mut body = json!({
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": true,
        });
        if !tools.is_empty() {
            body["tools"] = Value::Array(tools.to_vec());
        }
        let rb = self.auth(
            self.egress
                .post(&format!("{}/chat/completions", self.base))?,
        );
        let mut resp = rb
            .json(&body)
            .send()
            .await
            .map_err(|e| LlmError::Http(crate::sanitizer::redact(&e.to_string())))?;
        let status = resp.status();
        let is_sse = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/event-stream"));
        if !status.is_success() || !is_sse {
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
            let r = parse_chat(&v)?;
            on_delta(&r.content);
            return Ok(r);
        }
        let mut acc = SseChat::default();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| LlmError::Http(crate::sanitizer::redact(&e.to_string())))?
        {
            if acc.feed(&chunk, on_delta)? {
                break;
            }
        }
        acc.finish()
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

/// Incremental parser for an OpenAI-style `chat/completions` SSE stream.
#[derive(Default)]
pub struct SseChat {
    buf: Vec<u8>,
    total: usize,
    content: String,
    model: String,
    calls: Vec<(String, String, String)>,
    done: bool,
}

/// Upper bound on a streamed reply; a runaway server is cut off.
const MAX_SSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_STREAM_TOOL_CALLS: usize = 32;

impl SseChat {
    /// Feed raw bytes; returns true once `[DONE]` was seen.
    pub fn feed(
        &mut self,
        bytes: &[u8],
        on_delta: &mut (dyn FnMut(&str) + Send),
    ) -> Result<bool, LlmError> {
        self.total += bytes.len();
        if self.total > MAX_SSE_BYTES {
            return Err(LlmError::Http("streamed reply too large".into()));
        }
        self.buf.extend_from_slice(bytes);
        while let Some(nl) = self.buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=nl).collect();
            let line = String::from_utf8_lossy(&line);
            let line = line.trim_end_matches(['\r', '\n']);
            let Some(data) = line.strip_prefix("data:") else {
                continue; // comments, event:, id:, blank separators
            };
            let data = data.trim_start();
            if data == "[DONE]" {
                self.done = true;
                return Ok(true);
            }
            let v: Value = serde_json::from_str(data).map_err(|_| LlmError::Shape)?;
            if !v["error"].is_null() {
                let msg = v["error"]["message"]
                    .as_str()
                    .or(v["error"].as_str())
                    .unwrap_or("stream error");
                return Err(LlmError::Http(crate::sanitizer::redact(msg)));
            }
            if let Some(m) = v["model"].as_str()
                && self.model.is_empty()
            {
                self.model = m.to_string();
            }
            let d = &v["choices"][0]["delta"];
            if let Some(t) = d["content"].as_str()
                && !t.is_empty()
            {
                self.content.push_str(t);
                on_delta(t);
            }
            for c in d["tool_calls"].as_array().into_iter().flatten() {
                let i = c["index"].as_u64().unwrap_or(0) as usize;
                if i >= MAX_STREAM_TOOL_CALLS {
                    return Err(LlmError::Shape);
                }
                while self.calls.len() <= i {
                    self.calls.push(Default::default());
                }
                let slot = &mut self.calls[i];
                if let Some(id) = c["id"].as_str() {
                    slot.0 = id.to_string();
                }
                if let Some(n) = c["function"]["name"].as_str() {
                    slot.1.push_str(n);
                }
                match &c["function"]["arguments"] {
                    Value::String(a) => slot.2.push_str(a),
                    Value::Null => {}
                    other => slot.2.push_str(&other.to_string()),
                }
            }
        }
        Ok(false)
    }

    pub fn finish(self) -> Result<ChatReply, LlmError> {
        if !self.done && self.content.is_empty() && self.calls.is_empty() {
            return Err(LlmError::Shape);
        }
        let tool_calls = self
            .calls
            .into_iter()
            .enumerate()
            .filter(|(_, c)| !c.1.is_empty())
            .map(|(i, (id, name, args))| ToolCall {
                id: if id.is_empty() {
                    format!("call_{i}")
                } else {
                    id
                },
                name,
                arguments: if args.is_empty() { "{}".into() } else { args },
            })
            .collect();
        Ok(ChatReply {
            content: strip_thinking(&self.content),
            tool_calls,
            model: self.model,
        })
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
    fn sse_stream_accumulates_content_and_tool_calls_across_chunk_splits() {
        let wire = concat!(
            ": keep-alive\r\n\r\n",
            "data: {\"model\":\"qwen\",\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"<think>x</think>Hel\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"t1\",\"function\":{\"name\":\"web_\",\"arguments\":\"{\\\"q\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"search\",\"arguments\":\"\\\":1}\"}}]}}]}\n\n",
            "data: [DONE]\n\n",
        );
        // Feed in 7-byte slices so lines and UTF-8 straddle chunk borders.
        let mut acc = SseChat::default();
        let mut seen = String::new();
        let mut cb = |t: &str| seen.push_str(t);
        let mut done = false;
        for part in wire.as_bytes().chunks(7) {
            done = acc.feed(part, &mut cb).expect("feed");
            if done {
                break;
            }
        }
        assert!(done);
        let r = acc.finish().expect("finish");
        assert_eq!(
            seen, "<think>x</think>Hello",
            "raw deltas; the guard strips"
        );
        assert_eq!(r.content, "Hello");
        assert_eq!(r.model, "qwen");
        assert_eq!(r.tool_calls.len(), 1);
        assert_eq!(r.tool_calls[0].name, "web_search");
        assert_eq!(r.tool_calls[0].arguments, "{\"q\":1}");
    }

    #[test]
    fn sse_stream_errors_are_redacted_and_bounded() {
        let mut acc = SseChat::default();
        let mut cb = |_: &str| {};
        // Synthetic key assembled at runtime so secret scanners don't flag the source.
        let line = format!(
            "data: {{\"error\":{{\"message\":\"bad key {}{}\"}}}}\n",
            "sk-ant-", "AAAAAAAAAAAAAAAAAAAAAAAA"
        );
        let e = acc.feed(line.as_bytes(), &mut cb).expect_err("error event");
        assert!(!e.to_string().contains("sk-ant-AAAA"), "{e}");
        let mut acc = SseChat::default();
        let big = vec![b'x'; MAX_SSE_BYTES + 1];
        assert!(acc.feed(&big, &mut cb).is_err());
        assert!(
            SseChat::default().finish().is_err(),
            "empty stream is not a reply"
        );
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
