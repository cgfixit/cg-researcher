//! cg-core: config, policy, RAG, model clients and the agent graph.
//! Connectors live in `cg-connectors`; this crate must never depend on it (I6).
#![forbid(unsafe_code)]

pub mod agent;
pub mod attachments;
pub mod config;
pub mod egress;
pub mod fsutil;
pub mod llm;
pub mod paths;
pub mod rag;
pub mod sandbox;
pub mod sanitizer;
pub mod secrets;
pub mod tools;
