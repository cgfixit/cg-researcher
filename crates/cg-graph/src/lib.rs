//! A small, typed LangGraph-style state machine.
//!
//! There is no maintained Rust port of LangGraph, so this crate keeps the
//! *shape* CyClaw relies on: named nodes, fixed edges, conditional edges with
//! a declared target set, one entry point and one sink. The difference is that
//! the topology rules CyClaw proves with AST tests are checked here when the
//! graph is compiled, and again at run time:
//!
//! * exactly one entry node (I1: the caller picks `retrieve`);
//! * every conditional edge declares its targets, and a router that returns an
//!   undeclared target is a hard error, never a silent detour (I2);
//! * every node can reach the sink, the sink's only edge is `END`, and no other
//!   node edges to `END` (I4: audit convergence);
//! * a step budget stops cycles (the tool loop) from spinning forever.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use futures::future::BoxFuture;

/// The terminal pseudo-node.
pub const END: &str = "__end__";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GraphError {
    #[error("node `{0}` is defined twice")]
    DuplicateNode(String),
    #[error("edge references unknown node `{0}`")]
    UnknownNode(String),
    #[error("entry point is not set")]
    NoEntry,
    #[error("sink is not set")]
    NoSink,
    #[error("node `{0}` has no outgoing edge")]
    DanglingNode(String),
    #[error("node `{0}` has more than one outgoing edge definition")]
    MultipleEdges(String),
    #[error("node `{0}` cannot reach the sink `{1}`")]
    SinkUnreachable(String, String),
    #[error("only the sink may edge to END, but `{0}` does")]
    EndBypassesSink(String),
    #[error("the sink must edge only to END")]
    SinkNotTerminal,
    #[error("node `{0}` is unreachable from the entry")]
    Unreachable(String),
    #[error("router on `{from}` returned undeclared target `{to}`")]
    UndeclaredTarget { from: String, to: String },
    #[error("step budget of {0} exhausted")]
    StepBudget(usize),
}

pub type NodeFn<S> = Arc<dyn Fn(S) -> BoxFuture<'static, S> + Send + Sync>;
pub type RouterFn<S> = Arc<dyn Fn(&S) -> &'static str + Send + Sync>;

enum Edge<S> {
    Fixed(&'static str),
    Conditional {
        router: RouterFn<S>,
        targets: BTreeSet<&'static str>,
    },
}

pub struct StateGraph<S> {
    nodes: BTreeMap<&'static str, NodeFn<S>>,
    edges: BTreeMap<&'static str, Edge<S>>,
    entry: Option<&'static str>,
    sink: Option<&'static str>,
    errors: Vec<GraphError>,
}

impl<S: Send + 'static> Default for StateGraph<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Send + 'static> StateGraph<S> {
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            entry: None,
            sink: None,
            errors: Vec::new(),
        }
    }

    pub fn add_node<F, Fut>(&mut self, name: &'static str, f: F) -> &mut Self
    where
        F: Fn(S) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = S> + Send + 'static,
    {
        if self.nodes.contains_key(name) {
            self.errors.push(GraphError::DuplicateNode(name.into()));
        }
        self.nodes.insert(name, Arc::new(move |s| Box::pin(f(s))));
        self
    }

    fn set_edge(&mut self, from: &'static str, edge: Edge<S>) {
        if self.edges.insert(from, edge).is_some() {
            self.errors.push(GraphError::MultipleEdges(from.into()));
        }
    }

    pub fn add_edge(&mut self, from: &'static str, to: &'static str) -> &mut Self {
        self.set_edge(from, Edge::Fixed(to));
        self
    }

    pub fn add_conditional_edges<R>(
        &mut self,
        from: &'static str,
        router: R,
        targets: &[&'static str],
    ) -> &mut Self
    where
        R: Fn(&S) -> &'static str + Send + Sync + 'static,
    {
        self.set_edge(
            from,
            Edge::Conditional {
                router: Arc::new(router),
                targets: targets.iter().copied().collect(),
            },
        );
        self
    }

    pub fn set_entry_point(&mut self, name: &'static str) -> &mut Self {
        self.entry = Some(name);
        self
    }

    /// The single convergence node (CyClaw's `audit_logger`).
    pub fn set_sink(&mut self, name: &'static str) -> &mut Self {
        self.sink = Some(name);
        self
    }

    fn targets(edge: &Edge<S>) -> Vec<&'static str> {
        match edge {
            Edge::Fixed(t) => vec![*t],
            Edge::Conditional { targets, .. } => targets.iter().copied().collect(),
        }
    }

    pub fn compile(self) -> Result<CompiledGraph<S>, GraphError> {
        if let Some(e) = self.errors.into_iter().next() {
            return Err(e);
        }
        let entry = self.entry.ok_or(GraphError::NoEntry)?;
        let sink = self.sink.ok_or(GraphError::NoSink)?;
        for name in [entry, sink] {
            if !self.nodes.contains_key(name) {
                return Err(GraphError::UnknownNode(name.into()));
            }
        }
        for (from, edge) in &self.edges {
            if !self.nodes.contains_key(from) {
                return Err(GraphError::UnknownNode((*from).into()));
            }
            for t in Self::targets(edge) {
                if t != END && !self.nodes.contains_key(t) {
                    return Err(GraphError::UnknownNode(t.into()));
                }
                if t == END && *from != sink {
                    return Err(GraphError::EndBypassesSink((*from).into()));
                }
            }
        }
        for name in self.nodes.keys() {
            if !self.edges.contains_key(name) {
                return Err(GraphError::DanglingNode((*name).into()));
            }
        }
        match self.edges.get(sink) {
            Some(Edge::Fixed(t)) if *t == END => {}
            _ => return Err(GraphError::SinkNotTerminal),
        }
        // Reachability from the entry.
        let mut seen = BTreeSet::new();
        let mut queue = VecDeque::from([entry]);
        while let Some(n) = queue.pop_front() {
            if n == END || !seen.insert(n) {
                continue;
            }
            if let Some(e) = self.edges.get(n) {
                queue.extend(Self::targets(e));
            }
        }
        for name in self.nodes.keys() {
            if !seen.contains(name) {
                return Err(GraphError::Unreachable((*name).into()));
            }
        }
        // Every node reaches the sink (reverse BFS from the sink).
        let mut reaches = BTreeSet::from([sink]);
        loop {
            let before = reaches.len();
            for (from, edge) in &self.edges {
                if Self::targets(edge).iter().any(|t| reaches.contains(t)) {
                    reaches.insert(*from);
                }
            }
            if reaches.len() == before {
                break;
            }
        }
        for name in self.nodes.keys() {
            if !reaches.contains(name) {
                return Err(GraphError::SinkUnreachable((*name).into(), sink.into()));
            }
        }
        Ok(CompiledGraph {
            nodes: self.nodes,
            edges: self.edges,
            entry,
            sink,
        })
    }
}

/// A validated graph. Immutable after compile.
pub struct CompiledGraph<S> {
    nodes: BTreeMap<&'static str, NodeFn<S>>,
    edges: BTreeMap<&'static str, Edge<S>>,
    entry: &'static str,
    sink: &'static str,
}

/// What a run did, for the audit record and tests.
#[derive(Debug, Clone)]
pub struct Trace {
    pub path: Vec<&'static str>,
}

impl<S: Send + 'static> CompiledGraph<S> {
    pub fn entry(&self) -> &'static str {
        self.entry
    }
    pub fn sink(&self) -> &'static str {
        self.sink
    }
    pub fn node_names(&self) -> Vec<&'static str> {
        self.nodes.keys().copied().collect()
    }
    /// Nodes in breadth-first order from the entry, sink last; for display.
    pub fn flow_order(&self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = Vec::with_capacity(self.nodes.len());
        let mut queue = std::collections::VecDeque::from([self.entry]);
        while let Some(n) = queue.pop_front() {
            if n == self.sink || out.contains(&n) {
                continue;
            }
            out.push(n);
            queue.extend(self.successors(n));
        }
        for n in self.nodes.keys() {
            if *n != self.sink && !out.contains(n) {
                out.push(n);
            }
        }
        out.push(self.sink);
        out
    }
    /// Declared successors of a node (for invariant tests).
    pub fn successors(&self, node: &str) -> Vec<&'static str> {
        self.edges
            .get(node)
            .map(StateGraph::<S>::targets)
            .unwrap_or_default()
    }

    /// Run from the entry. When the step budget runs out the state is sent
    /// straight to the sink so the run is still audited; the error is
    /// returned alongside the final state.
    pub async fn invoke(&self, mut state: S, max_steps: usize) -> (S, Trace, Option<GraphError>) {
        let mut trace = Trace { path: Vec::new() };
        let mut current = self.entry;
        let mut failure = None;
        loop {
            if current == END {
                break;
            }
            if trace.path.len() >= max_steps && current != self.sink {
                failure = Some(GraphError::StepBudget(max_steps));
                current = self.sink;
            }
            trace.path.push(current);
            let node = self.nodes[current].clone();
            state = node(state).await;
            let next = match &self.edges[current] {
                Edge::Fixed(t) => *t,
                Edge::Conditional { router, targets } => {
                    let t = router(&state);
                    if targets.contains(t) {
                        t
                    } else {
                        // Fail closed: an undeclared route goes to the sink.
                        failure = Some(GraphError::UndeclaredTarget {
                            from: current.into(),
                            to: t.into(),
                        });
                        self.sink
                    }
                }
            };
            if current == self.sink {
                break;
            }
            current = next;
        }
        (state, trace, failure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> StateGraph<u32> {
        let mut g = StateGraph::new();
        g.add_node("a", |s| async move { s + 1 })
            .add_node("b", |s| async move { s * 2 })
            .add_node("audit", |s| async move { s })
            .set_entry_point("a")
            .set_sink("audit");
        g
    }

    #[test]
    fn valid_graph_compiles() {
        let mut g = base();
        g.add_edge("a", "b")
            .add_edge("b", "audit")
            .add_edge("audit", END);
        assert!(g.compile().is_ok());
    }

    #[test]
    fn end_edge_that_skips_the_sink_is_refused() {
        let mut g = base();
        g.add_edge("a", "b")
            .add_edge("b", END)
            .add_edge("audit", END);
        assert_eq!(
            g.compile().err(),
            Some(GraphError::EndBypassesSink("b".into()))
        );
    }

    #[test]
    fn sink_with_outgoing_non_end_edge_is_refused() {
        let mut g = base();
        g.add_edge("a", "b")
            .add_edge("b", "audit")
            .add_edge("audit", "a");
        assert_eq!(g.compile().err(), Some(GraphError::SinkNotTerminal));
    }

    #[test]
    fn unreachable_node_is_refused() {
        let mut g = base();
        g.add_node("orphan", |s| async move { s });
        g.add_edge("a", "audit")
            .add_edge("b", "audit")
            .add_edge("orphan", "audit")
            .add_edge("audit", END);
        assert!(matches!(
            g.compile().err(),
            Some(GraphError::Unreachable(_))
        ));
    }

    #[test]
    fn undeclared_router_target_fails_closed_to_sink() {
        let mut g = base();
        g.add_conditional_edges("a", |_| "b_typo", &["b"])
            .add_edge("b", "audit")
            .add_edge("audit", END);
        let c = g.compile().expect("compiles");
        let (s, t, e) = futures::executor::block_on(c.invoke(1, 10));
        assert_eq!(s, 2);
        assert_eq!(t.path, vec!["a", "audit"]);
        assert!(matches!(e, Some(GraphError::UndeclaredTarget { .. })));
    }

    #[test]
    fn cycle_is_bounded_and_still_audits() {
        let mut g = base();
        g.add_edge("a", "b")
            .add_conditional_edges("b", |_| "a", &["a", "audit"])
            .add_edge("audit", END);
        let c = g.compile().expect("compiles");
        let (_, t, e) = futures::executor::block_on(c.invoke(0, 6));
        assert_eq!(t.path.last(), Some(&"audit"));
        assert_eq!(e, Some(GraphError::StepBudget(6)));
    }

    #[test]
    fn flow_order_starts_at_entry_and_ends_at_sink() {
        let mut g: StateGraph<u32> = StateGraph::new();
        g.add_node("z_start", |s| async move { s })
            .add_node("a_mid", |s| async move { s })
            .add_node("m_end", |s| async move { s })
            .set_entry_point("z_start")
            .set_sink("m_end")
            .add_edge("z_start", "a_mid")
            .add_edge("a_mid", "m_end")
            .add_edge("m_end", END);
        let c = g.compile().expect("compile");
        assert_eq!(c.flow_order(), vec!["z_start", "a_mid", "m_end"]);
        assert_eq!(c.node_names(), vec!["a_mid", "m_end", "z_start"]);
    }
}
