//! Conversion Service Unique-flight fill session.
//!
//! HTTP drives this plan: Outbound accept and unique fetches, feeding bodies.
//! The session names No remote config versus Rule frontend and Keep-pass; HTTP
//! does not, after [`UniqueFlightSessionV1::start`].

use std::fmt;

use super::{UniqueFlightFillV1, UniqueFlightPrefix};
use crate::{
    Acl4SsrPreparationError, Acl4SsrRenderError, Acl4SsrRuleSetBinder, ConversionRenderError,
    OutputTarget, PreparedAcl4SsrRuleSetsV1, PreparedAcl4SsrV1, PreparedSubscriptionV1,
    RenderedConfig, SubscriptionPreparationError,
};

/// Unique-flight fill session: bind → fill → prefix / grammar-beats-budget →
/// prepare / decoded accounts → Keep-pass.
pub struct UniqueFlightSessionV1 {
    sources: Vec<String>,
    config_canonical: Option<String>,
    target: OutputTarget,
    stage: Option<Stage>,
}

enum Stage {
    FetchSubscription(UniqueFlightFillV1),
    FetchConfig {
        prepared: PreparedSubscriptionV1,
        fill: UniqueFlightFillV1,
    },
    AcceptRuleSets(Acl4SsrRuleSetBinder),
    FetchRuleSets {
        bound: PreparedAcl4SsrRuleSetsV1,
        loaded: Vec<Vec<u8>>,
    },
    Ready(RenderedConfig),
}

/// Resource kind of the Unique flights the session currently needs filled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UniqueFlightKind {
    Subscription,
    Config,
    RuleSet,
}

/// What HTTP must do before the session can advance.
pub enum UniqueFlightNeed<'a> {
    Fetch {
        kind: UniqueFlightKind,
        urls: &'a [String],
    },
    AcceptRuleSet {
        url: &'a str,
    },
    Ready,
}

/// Closed Unique-flight session failure. HTTP maps this onto GET once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UniqueFlightSessionError {
    Misaligned,
    Subscription(SubscriptionPreparationError),
    Config(Acl4SsrPreparationError),
    RuleSet(Acl4SsrRenderError),
    Render(ConversionRenderError),
}

impl UniqueFlightSessionV1 {
    /// Bind subscription occurrences. Config is one Unique flight on the same plan.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the direct-only prefix is already invalid, or
    /// when Keep-pass can complete without a remote fetch and that render fails.
    pub fn start<'a, I>(
        sources: &[String],
        occurrence_canonical: I,
        config_canonical: Option<&str>,
        target: OutputTarget,
    ) -> Result<Self, UniqueFlightSessionError>
    where
        I: IntoIterator<Item = Option<&'a str>>,
    {
        let fill = UniqueFlightFillV1::bind_optional(occurrence_canonical);
        let empty_uniques = fill.unique_urls().is_empty();
        let mut session = Self {
            sources: sources.to_vec(),
            config_canonical: config_canonical.map(str::to_owned),
            target,
            stage: Some(Stage::FetchSubscription(fill)),
        };
        if empty_uniques {
            let sizes = session.feed_unique_bodies(&[])?;
            debug_assert!(sizes.is_empty());
        }
        Ok(session)
    }

    #[must_use]
    pub fn need(&self) -> UniqueFlightNeed<'_> {
        match self.stage.as_ref() {
            Some(Stage::FetchSubscription(fill)) => UniqueFlightNeed::Fetch {
                kind: UniqueFlightKind::Subscription,
                urls: fill.unique_urls(),
            },
            Some(Stage::FetchConfig { fill, .. }) => UniqueFlightNeed::Fetch {
                kind: UniqueFlightKind::Config,
                urls: fill.unique_urls(),
            },
            Some(Stage::AcceptRuleSets(binder)) => match binder.next_occurrence_url() {
                Some(url) => UniqueFlightNeed::AcceptRuleSet { url },
                None => UniqueFlightNeed::Ready,
            },
            Some(Stage::FetchRuleSets { bound, .. }) => UniqueFlightNeed::Fetch {
                kind: UniqueFlightKind::RuleSet,
                urls: bound.unique_urls(),
            },
            Some(Stage::Ready(_)) | None => UniqueFlightNeed::Ready,
        }
    }

    /// Unique bodies in first-seen order for the current Fetch need.
    ///
    /// Returns first-seen decoded sizes for HTTP to account. Config and Rule Set
    /// sizes are the body lengths.
    ///
    /// # Errors
    ///
    /// Alignment, prepare, Rule frontend, or Keep-pass failures.
    pub fn feed_unique_bodies(
        &mut self,
        bodies: &[Vec<u8>],
    ) -> Result<Vec<usize>, UniqueFlightSessionError> {
        match self.stage.as_ref() {
            Some(Stage::FetchSubscription(_)) => self.feed_subscription(bodies),
            Some(Stage::FetchConfig { .. }) => self.feed_config(bodies),
            Some(Stage::FetchRuleSets { .. } | Stage::AcceptRuleSets(_) | Stage::Ready(_))
            | None => Err(UniqueFlightSessionError::Misaligned),
        }
    }

    /// Prefix grammar-beats-budget for loaded Rule Set unique bodies.
    ///
    /// When the prefix is complete, Keep-pass runs here.
    ///
    /// # Errors
    ///
    /// Rule Set stage or Keep-pass failures, or alignment if this is not the
    /// Rule Set fetch stage.
    pub fn feed_rule_set_prefix(
        &mut self,
        bodies: &[&[u8]],
        already_accounted_unique: usize,
        already_decoded_bytes: usize,
        decoded_byte_cap: usize,
    ) -> Result<(), UniqueFlightSessionError> {
        let unique_count = match self.stage.as_ref() {
            Some(Stage::FetchRuleSets { bound, .. }) => bound.unique_urls().len(),
            _ => return Err(UniqueFlightSessionError::Misaligned),
        };
        let Some(Stage::FetchRuleSets { bound, loaded }) = self.stage.as_mut() else {
            return Err(UniqueFlightSessionError::Misaligned);
        };
        bound
            .check_loaded_prefix_with_decoded_budget(
                bodies,
                already_accounted_unique,
                already_decoded_bytes,
                decoded_byte_cap,
            )
            .map_err(UniqueFlightSessionError::RuleSet)?;
        loaded.clear();
        loaded.extend(bodies.iter().map(|body| body.to_vec()));
        if loaded.len() == unique_count {
            self.finish_rule_sets()?;
        }
        Ok(())
    }

    /// Outbound-accepted canonical Rule Set occurrence. Returns unique-flight count.
    ///
    /// # Errors
    ///
    /// Alignment, unique-table, or Keep-pass when this push completes a config
    /// with no remote Rule Set bodies.
    pub fn push_rule_set_canonical(
        &mut self,
        url: &str,
    ) -> Result<usize, UniqueFlightSessionError> {
        let Some(Stage::AcceptRuleSets(binder)) = self.stage.as_mut() else {
            return Err(UniqueFlightSessionError::Misaligned);
        };
        let unique_count = binder
            .push_canonical(url)
            .map_err(UniqueFlightSessionError::RuleSet)?;
        if binder.next_occurrence_url().is_some() {
            return Ok(unique_count);
        }
        let Some(Stage::AcceptRuleSets(binder)) = self.stage.take() else {
            return Err(UniqueFlightSessionError::Misaligned);
        };
        let bound = binder.finish().map_err(UniqueFlightSessionError::RuleSet)?;
        if bound.unique_urls().is_empty() {
            self.render_rule_sets(bound, &[])?;
        } else {
            self.stage = Some(Stage::FetchRuleSets {
                bound,
                loaded: Vec::new(),
            });
        }
        Ok(unique_count)
    }

    /// Subscription prefix when a later unique fetch fails.
    #[must_use]
    pub fn fail_subscription_prefix(
        &self,
        loaded: &[Option<impl AsRef<[u8]>>],
        failed_unique_index: usize,
    ) -> UniqueFlightPrefix {
        match self.stage.as_ref() {
            Some(Stage::FetchSubscription(fill)) => {
                fill.prefix_error_before_unique_failure(&self.sources, loaded, failed_unique_index)
            }
            _ => UniqueFlightPrefix::Misaligned,
        }
    }

    /// Keep-pass document. Session must be [`UniqueFlightNeed::Ready`].
    ///
    /// # Errors
    ///
    /// [`UniqueFlightSessionError::Misaligned`] when Keep-pass has not run.
    pub fn into_document(self) -> Result<RenderedConfig, UniqueFlightSessionError> {
        match self.stage {
            Some(Stage::Ready(document)) => Ok(document),
            _ => Err(UniqueFlightSessionError::Misaligned),
        }
    }

    fn feed_subscription(
        &mut self,
        bodies: &[Vec<u8>],
    ) -> Result<Vec<usize>, UniqueFlightSessionError> {
        let Some(Stage::FetchSubscription(fill)) = self.stage.take() else {
            return Err(UniqueFlightSessionError::Misaligned);
        };
        if bodies.len() != fill.unique_urls().len() {
            self.stage = Some(Stage::FetchSubscription(fill));
            return Err(UniqueFlightSessionError::Misaligned);
        }
        let prepared = match fill.prepare_subscription(&self.sources, bodies) {
            None => {
                self.stage = Some(Stage::FetchSubscription(fill));
                return Err(UniqueFlightSessionError::Misaligned);
            }
            Some(Err(error)) => {
                self.stage = Some(Stage::FetchSubscription(fill));
                return Err(UniqueFlightSessionError::Subscription(error));
            }
            Some(Ok(prepared)) => prepared,
        };
        let Some(sizes) = fill.unique_decoded_bytes(&prepared) else {
            self.stage = Some(Stage::FetchSubscription(fill));
            return Err(UniqueFlightSessionError::Misaligned);
        };
        self.advance_after_subscription(prepared)?;
        Ok(sizes)
    }

    fn feed_config(&mut self, bodies: &[Vec<u8>]) -> Result<Vec<usize>, UniqueFlightSessionError> {
        let Some(Stage::FetchConfig { fill, .. }) = self.stage.as_ref() else {
            return Err(UniqueFlightSessionError::Misaligned);
        };
        if bodies.len() != fill.unique_urls().len() {
            return Err(UniqueFlightSessionError::Misaligned);
        }
        let Some(body) = bodies.first() else {
            return Err(UniqueFlightSessionError::Misaligned);
        };
        let size = body.len();
        let Some(Stage::FetchConfig { prepared, fill: _ }) = self.stage.take() else {
            return Err(UniqueFlightSessionError::Misaligned);
        };
        let prepared = prepared
            .prepare_acl4ssr_config_v1(body)
            .map_err(UniqueFlightSessionError::Config)?;
        self.advance_after_config(prepared)?;
        Ok(vec![size])
    }

    fn advance_after_subscription(
        &mut self,
        prepared: PreparedSubscriptionV1,
    ) -> Result<(), UniqueFlightSessionError> {
        match self.config_canonical.as_deref() {
            None => {
                let document = prepared
                    .render_builtin_v1(self.target)
                    .map_err(UniqueFlightSessionError::Render)?;
                self.stage = Some(Stage::Ready(document));
            }
            Some(config) => {
                self.stage = Some(Stage::FetchConfig {
                    prepared,
                    fill: UniqueFlightFillV1::bind_remote([config]),
                });
            }
        }
        Ok(())
    }

    fn advance_after_config(
        &mut self,
        prepared: PreparedAcl4SsrV1,
    ) -> Result<(), UniqueFlightSessionError> {
        if prepared.rule_set_requests().is_empty() {
            let bound = prepared
                .rule_set_binder()
                .finish()
                .map_err(UniqueFlightSessionError::RuleSet)?;
            self.render_rule_sets(bound, &[])?;
        } else {
            self.stage = Some(Stage::AcceptRuleSets(prepared.rule_set_binder()));
        }
        Ok(())
    }

    fn finish_rule_sets(&mut self) -> Result<(), UniqueFlightSessionError> {
        let Some(Stage::FetchRuleSets { bound, loaded }) = self.stage.take() else {
            return Err(UniqueFlightSessionError::Misaligned);
        };
        let bodies = loaded.iter().map(Vec::as_slice).collect::<Vec<_>>();
        self.render_rule_sets(bound, &bodies)
    }

    fn render_rule_sets(
        &mut self,
        bound: PreparedAcl4SsrRuleSetsV1,
        bodies: &[&[u8]],
    ) -> Result<(), UniqueFlightSessionError> {
        let document = bound
            .render_v1(self.target, bodies)
            .map_err(UniqueFlightSessionError::RuleSet)?;
        self.stage = Some(Stage::Ready(document));
        Ok(())
    }
}

impl fmt::Debug for UniqueFlightSessionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stage = match self.stage.as_ref() {
            Some(Stage::FetchSubscription(_)) => "fetch_subscription",
            Some(Stage::FetchConfig { .. }) => "fetch_config",
            Some(Stage::AcceptRuleSets(_)) => "accept_rule_sets",
            Some(Stage::FetchRuleSets { .. }) => "fetch_rule_sets",
            Some(Stage::Ready(_)) => "ready",
            None => "unset",
        };
        formatter
            .debug_struct("UniqueFlightSessionV1")
            .field("source_count", &self.sources.len())
            .field("has_config", &self.config_canonical.is_some())
            .field("target", &self.target)
            .field("stage", &stage)
            .finish()
    }
}

impl fmt::Debug for UniqueFlightNeed<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fetch { kind, urls } => formatter
                .debug_struct("Fetch")
                .field("kind", kind)
                .field("unique_count", &urls.len())
                .finish(),
            Self::AcceptRuleSet { .. } => formatter
                .debug_struct("AcceptRuleSet")
                .field("url", &"[REDACTED]")
                .finish(),
            Self::Ready => formatter.write_str("Ready"),
        }
    }
}

impl fmt::Display for UniqueFlightSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Misaligned => formatter.write_str("unique-flight session is misaligned"),
            Self::Subscription(error) => error.fmt(formatter),
            Self::Config(error) => error.fmt(formatter),
            Self::RuleSet(error) => error.fmt(formatter),
            Self::Render(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for UniqueFlightSessionError {}
