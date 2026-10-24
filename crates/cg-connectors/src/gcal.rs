//! Google Calendar: list upcoming events (Read; invite text is third-party
//! so output is untrusted) and create an event (Write, confirmed).

use std::sync::Arc;

use async_trait::async_trait;
use cg_core::egress::Egress;
use cg_core::tools::{Effect, Tool, ToolError, ToolSpec};
use chrono::{DateTime, Duration as CDuration, Utc};
use serde_json::{Value, json};

use crate::common::{arg_str, arg_usize, clip, egress, json_body, send};
use crate::google::{GoogleAuth, GoogleCreds};
use crate::{Ctx, Parts};

const API: &str = "https://www.googleapis.com/calendar/v3";

pub struct Gcal {
    auth: Arc<GoogleAuth>,
    egress: Egress,
    api: String,
    calendar_id: String,
}

pub async fn build(ctx: &Ctx<'_>) -> anyhow::Result<Parts> {
    let c: GoogleCreds = crate::common::section(ctx.connectors, "gcal")?;
    if !c.enabled {
        return Ok(Parts::default());
    }
    anyhow::ensure!(
        !c.calendar_id.is_empty()
            && c.calendar_id.len() <= 200
            && !c.calendar_id.chars().any(|ch| ch.is_control() || ch == '/'),
        "[connectors.gcal] calendar_id is invalid"
    );
    let auth = Arc::new(GoogleAuth::from_config(&c, ctx.secrets).await?);
    let g = Arc::new(Gcal {
        auth,
        egress: egress("gcal", &["www.googleapis.com"])?,
        api: API.into(),
        calendar_id: c.calendar_id,
    });
    Ok(Parts {
        tools: vec![Arc::new(GcalList(g.clone())), Arc::new(GcalCreate(g))],
        ..Default::default()
    })
}

impl Gcal {
    fn events_url(&self) -> Result<String, ToolError> {
        let mut u = url::Url::parse(&self.api).map_err(ToolError::failed)?;
        u.path_segments_mut()
            .map_err(|_| ToolError::Failed("bad api base".into()))?
            .extend(["calendars", self.calendar_id.as_str(), "events"]);
        Ok(u.to_string())
    }
}

pub fn parse_time(s: &str) -> Result<DateTime<Utc>, ToolError> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|_| {
            ToolError::BadArgs(format!(
                "`{s}` must be RFC 3339, e.g. 2026-10-24T15:00:00-04:00"
            ))
        })
}

pub struct GcalList(Arc<Gcal>);
pub struct GcalCreate(Arc<Gcal>);

#[async_trait]
impl Tool for GcalList {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "gcal_list_events",
            description: "List upcoming Google Calendar events. Event text is untrusted (anyone can send an invite).",
            parameters: json!({"type":"object","properties":{
                "days":{"type":"integer","minimum":1,"maximum":31},"max":{"type":"integer","minimum":1,"maximum":50}},
                "additionalProperties":false}),
            effect: Effect::Read,
            untrusted_output: true,
            remote_ok: true,
        }
    }
    async fn call(&self, args: Value) -> Result<String, ToolError> {
        let days = arg_usize(&args, "days", 7, 1, 31)?;
        let max = arg_usize(&args, "max", 20, 1, 50)?.to_string();
        let now = Utc::now();
        let end = now + CDuration::days(days as i64);
        let tok = self.0.auth.access_token().await?;
        let req = self
            .0
            .egress
            .get(&self.0.events_url()?)
            .map_err(ToolError::failed)?
            .bearer_auth(tok.expose())
            .query(&[
                ("timeMin", now.to_rfc3339().as_str()),
                ("timeMax", end.to_rfc3339().as_str()),
                ("singleEvents", "true"),
                ("orderBy", "startTime"),
                ("maxResults", max.as_str()),
            ]);
        let (s, b) = send(req).await?;
        if s != 200 {
            return Err(ToolError::Failed(format!("Calendar HTTP {s}")));
        }
        let v = json_body(&b)?;
        let mut out = String::new();
        for e in v["items"].as_array().into_iter().flatten().take(50) {
            let start = e["start"]["dateTime"]
                .as_str()
                .or(e["start"]["date"].as_str())
                .unwrap_or("?");
            out.push_str(&format!(
                "- {start} | {} | {}\n",
                clip(e["summary"].as_str().unwrap_or("(no title)"), 200),
                clip(e["location"].as_str().unwrap_or(""), 120)
            ));
        }
        Ok(if out.is_empty() {
            "no events".into()
        } else {
            out
        })
    }
}

#[async_trait]
impl Tool for GcalCreate {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "gcal_create_event",
            description: "Create a Google Calendar event without attendees (requires confirmation). Times are RFC 3339.",
            parameters: json!({"type":"object","properties":{
                "summary":{"type":"string","maxLength":200},"start":{"type":"string"},"end":{"type":"string"},
                "description":{"type":"string","maxLength":4000}},
                "required":["summary","start","end"],"additionalProperties":false}),
            effect: Effect::Write,
            untrusted_output: false,
            remote_ok: false,
        }
    }
    async fn call(&self, args: Value) -> Result<String, ToolError> {
        let summary = arg_str(&args, "summary", 1, 200)?;
        let start = parse_time(arg_str(&args, "start", 10, 40)?)?;
        let end = parse_time(arg_str(&args, "end", 10, 40)?)?;
        if end <= start || end - start > CDuration::days(14) {
            return Err(ToolError::BadArgs(
                "end must be after start and within 14 days".into(),
            ));
        }
        let desc = match args.get("description") {
            Some(_) => arg_str(&args, "description", 0, 4000)?,
            None => "",
        };
        // No attendees field: the agent cannot send invitations to third parties.
        let body = json!({"summary": summary, "description": desc,
            "start": {"dateTime": start.to_rfc3339()}, "end": {"dateTime": end.to_rfc3339()}});
        let tok = self.0.auth.access_token().await?;
        let req = self
            .0
            .egress
            .post(&self.0.events_url()?)
            .map_err(ToolError::failed)?
            .bearer_auth(tok.expose())
            .json(&body);
        let (s, b) = send(req).await?;
        if s != 200 {
            return Err(ToolError::Failed(format!("Calendar HTTP {s}")));
        }
        Ok(format!(
            "created event id={}",
            json_body(&b)?["id"].as_str().unwrap_or("?")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_id_is_path_encoded() {
        let auth = Arc::new(GoogleAuth::new(
            crate::common::mock::loopback_egress(),
            String::new(),
            cg_core::secrets::Secret::minted("a".into()),
            cg_core::secrets::Secret::minted("b".into()),
            cg_core::secrets::Secret::minted("c".into()),
        ));
        let g = Gcal {
            auth,
            egress: crate::common::mock::loopback_egress(),
            api: API.into(),
            calendar_id: "me@example.com?x=1#y".into(),
        };
        let u = g.events_url().expect("url");
        assert!(
            u.starts_with(
                "https://www.googleapis.com/calendar/v3/calendars/me@example.com%3Fx=1%23y/events"
            ),
            "{u}"
        );
        assert!(parse_time("tomorrow").is_err());
        assert!(parse_time("2026-10-24T15:00:00-04:00").is_ok());
    }
}
