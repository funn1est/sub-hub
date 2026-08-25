//! Conversion Service Unique-flight fill session.
//!
//! HTTP drives Outbound accept and unique fetches, then
//! [`UniqueFlightOutbound::fulfill`] / [`UniqueFlightOutbound::reject`] /
//! [`UniqueFlightFetch::fulfill`].
//! The session names No remote config versus Rule frontend and Keep-pass,
//! owns the decoded-byte tally, and decides Subscription user-info capture;
//! HTTP does not, after [`UniqueFlightSessionV1::start`].

use std::fmt;

use super::table::UniqueUrls;
use super::{UniqueFlightFillV1, UniqueFlightPrefix};
use crate::{
    Acl4SsrPreparationError, Acl4SsrRenderError, ConversionRenderError, MAX_CONFIG_BYTES,
    MAX_RULE_SET_BYTES, MAX_SUBSCRIPTION_INPUT_BYTES, OutputTarget, PreparedAcl4SsrRuleSetsV1,
    PreparedAcl4SsrV1, PreparedSubscriptionV1, RenderedConfig, SkipCountsV1,
    SubscriptionPreparationError,
};

/// Unique-flight fill session: bind → fill → prefix / grammar-beats-budget →
/// prepare / decoded accounts → Keep-pass.
pub struct UniqueFlightSessionV1 {
    state: SessionState,
    stage: Stage,
}

struct SessionState {
    sources: Vec<String>,
    config_canonical: Option<String>,
    unique_remotes: UniqueUrls,
    target: OutputTarget,
    decoded_byte_cap: usize,
    decoded_bytes: usize,
    accounted_unique: usize,
    append_subscription_user_info: bool,
}

enum Stage {
    FetchSubscription(UniqueFlightFillV1),
    FetchConfig {
        prepared: PreparedSubscriptionV1,
        fill: UniqueFlightFillV1,
    },
    AcceptRuleSets {
        prepared: PreparedAcl4SsrV1,
        fill: UniqueFlightFillV1,
        pending_url: String,
    },
    FetchRuleSets {
        bound: PreparedAcl4SsrRuleSetsV1,
        unique_urls: Vec<String>,
        loaded: Vec<Vec<u8>>,
    },
    Ready(RenderedConfig),
}

/// Move-only Unique-flight fill progress. HTTP drives [`Need`](Self::Need).
pub enum UniqueFlightDrive {
    Need(Box<UniqueFlightNeed>),
    Ended(Result<RenderedConfig, UniqueFlightFillFailure>),
}

/// One Host verb. HTTP does not name Subscription, Config, or Rule Set.
pub enum UniqueFlightNeed {
    Outbound(UniqueFlightOutbound),
    Fetch(UniqueFlightFetch),
}

/// One Outbound accept. Unique-capacity is part of this accept.
pub struct UniqueFlightOutbound {
    session: UniqueFlightSessionV1,
}

/// One unique fetch. Leftover first-seen URLs stay on this fetch for preflight.
pub struct UniqueFlightFetch {
    session: UniqueFlightSessionV1,
}

/// Unique bodies HTTP returns after a fetch hop.
#[derive(Clone, Copy)]
pub enum UniqueFlightBodies<'a> {
    Complete(&'a [&'a [u8]]),
    Failed {
        loaded: &'a [&'a [u8]],
        host: UniqueFlightHostFailure,
    },
}

/// Closed host fetch outcome when a unique hop fails. Session maps this into
/// [`UniqueFlightFillFailure`] unless a loaded prefix already beats it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UniqueFlightHostFailure {
    Failure,
    Timeout,
    ConversionLimit,
    Internal,
}

#[derive(Clone, Copy)]
enum HostEvent<'a> {
    Bodies(&'a [&'a [u8]]),
    FetchFailed {
        loaded: &'a [&'a [u8]],
        host: UniqueFlightHostFailure,
    },
    Accepted {
        url: &'a str,
    },
}

/// Closed Unique-flight fill failure. HTTP maps this onto GET once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UniqueFlightFillFailure {
    InvalidInput,
    ConversionLimit,
    RemoteFailure,
    RemoteTimeout,
    NoValidNodes { skips: SkipCountsV1 },
    Internal,
}

impl UniqueFlightFillFailure {
    const fn from_subscription(error: SubscriptionPreparationError) -> Self {
        match error {
            SubscriptionPreparationError::InvalidInput => Self::InvalidInput,
            SubscriptionPreparationError::RemoteFailure { .. } => Self::RemoteFailure,
            SubscriptionPreparationError::ConversionLimit => Self::ConversionLimit,
            SubscriptionPreparationError::NoValidNodes { skips } => Self::NoValidNodes { skips },
        }
    }

    const fn from_config(error: Acl4SsrPreparationError) -> Self {
        match error {
            Acl4SsrPreparationError::InvalidConfig => Self::InvalidInput,
            Acl4SsrPreparationError::ConversionLimit => Self::ConversionLimit,
            Acl4SsrPreparationError::Internal => Self::Internal,
        }
    }

    const fn from_rule_set(error: Acl4SsrRenderError) -> Self {
        match error {
            Acl4SsrRenderError::InvalidRuleSet => Self::InvalidInput,
            Acl4SsrRenderError::RuleSetAlignment | Acl4SsrRenderError::Internal => Self::Internal,
            Acl4SsrRenderError::ConversionLimit => Self::ConversionLimit,
            Acl4SsrRenderError::KeepPass(error) => Self::from_render(error),
        }
    }

    const fn from_render(error: ConversionRenderError) -> Self {
        match error {
            ConversionRenderError::ConversionLimit => Self::ConversionLimit,
            ConversionRenderError::NoValidNodes { skips } => Self::NoValidNodes { skips },
            ConversionRenderError::Internal => Self::Internal,
        }
    }

    const fn from_host(host: UniqueFlightHostFailure) -> Self {
        match host {
            UniqueFlightHostFailure::Failure => Self::RemoteFailure,
            UniqueFlightHostFailure::Timeout => Self::RemoteTimeout,
            UniqueFlightHostFailure::ConversionLimit => Self::ConversionLimit,
            UniqueFlightHostFailure::Internal => Self::Internal,
        }
    }
}

impl UniqueFlightSessionV1 {
    /// Bind subscription occurrences. Config is one Unique flight on the same plan.
    ///
    /// `decoded_byte_cap` is the Session budget decoded-byte cap. The session
    /// owns the running tally and whether the subscription hop may capture
    /// Subscription user-info; HTTP does not feed counts per step.
    #[must_use]
    pub fn start<'a, I>(
        sources: &[String],
        occurrence_canonical: I,
        config_canonical: Option<&str>,
        target: OutputTarget,
        decoded_byte_cap: usize,
        append_subscription_user_info: bool,
    ) -> UniqueFlightDrive
    where
        I: IntoIterator<Item = Option<&'a str>>,
    {
        match Self::bind(
            sources,
            occurrence_canonical,
            config_canonical,
            target,
            decoded_byte_cap,
            append_subscription_user_info,
        ) {
            Ok(session) => session.into_drive(),
            Err(failure) => UniqueFlightDrive::Ended(Err(failure)),
        }
    }

    fn bind<'a, I>(
        sources: &[String],
        occurrence_canonical: I,
        config_canonical: Option<&str>,
        target: OutputTarget,
        decoded_byte_cap: usize,
        append_subscription_user_info: bool,
    ) -> Result<Self, UniqueFlightFillFailure>
    where
        I: IntoIterator<Item = Option<&'a str>>,
    {
        let fill = UniqueFlightFillV1::bind_optional(occurrence_canonical);
        let unique_remotes = UniqueUrls::from_urls(fill.unique_urls().to_vec());
        let empty_uniques = unique_remotes.as_slice().is_empty();
        let session = Self {
            state: SessionState {
                sources: sources.to_vec(),
                config_canonical: config_canonical.map(str::to_owned),
                unique_remotes,
                target,
                decoded_byte_cap,
                decoded_bytes: 0,
                accounted_unique: 0,
                append_subscription_user_info,
            },
            stage: Stage::FetchSubscription(fill),
        };
        if empty_uniques {
            session.apply_event(HostEvent::Bodies(&[]))
        } else {
            Ok(session)
        }
    }

    fn into_drive(self) -> UniqueFlightDrive {
        let UniqueFlightSessionV1 { state, stage } = self;
        match stage {
            Stage::Ready(document) => UniqueFlightDrive::Ended(Ok(document)),
            Stage::AcceptRuleSets {
                pending_url,
                prepared,
                fill,
            } => {
                if pending_url.is_empty() {
                    UniqueFlightDrive::Ended(Err(UniqueFlightFillFailure::Internal))
                } else {
                    UniqueFlightDrive::Need(Box::new(UniqueFlightNeed::Outbound(
                        UniqueFlightOutbound {
                            session: UniqueFlightSessionV1 {
                                state,
                                stage: Stage::AcceptRuleSets {
                                    pending_url,
                                    prepared,
                                    fill,
                                },
                            },
                        },
                    )))
                }
            }
            stage @ (Stage::FetchSubscription(_)
            | Stage::FetchConfig { .. }
            | Stage::FetchRuleSets { .. }) => {
                UniqueFlightDrive::Need(Box::new(UniqueFlightNeed::Fetch(UniqueFlightFetch {
                    session: UniqueFlightSessionV1 { state, stage },
                })))
            }
        }
    }

    fn fetch_urls(&self) -> &[String] {
        match &self.stage {
            Stage::FetchSubscription(fill) | Stage::FetchConfig { fill, .. } => fill.unique_urls(),
            Stage::FetchRuleSets { unique_urls, .. } => unique_urls
                .get(self.state.accounted_unique..)
                .unwrap_or(&[]),
            Stage::AcceptRuleSets { .. } | Stage::Ready(_) => &[],
        }
    }

    fn fetch_max_body_bytes(&self) -> usize {
        match self.stage {
            Stage::FetchSubscription(_) => MAX_SUBSCRIPTION_INPUT_BYTES,
            Stage::FetchConfig { .. } => MAX_CONFIG_BYTES,
            Stage::FetchRuleSets { .. } => MAX_RULE_SET_BYTES,
            Stage::AcceptRuleSets { .. } | Stage::Ready(_) => 0,
        }
    }

    fn fetch_capture_subscription_user_info(&self) -> bool {
        match &self.stage {
            Stage::FetchSubscription(fill) => {
                self.state.append_subscription_user_info
                    && self.state.sources.len() == 1
                    && fill.unique_urls().len() == 1
            }
            _ => false,
        }
    }

    fn fetch_take_count(&self, session_concurrency: usize) -> usize {
        let n = self.fetch_urls().len();
        match self.stage {
            Stage::FetchSubscription(_) => n.max(1),
            Stage::FetchRuleSets { .. } => session_concurrency.min(n).max(1),
            Stage::FetchConfig { .. } | Stage::AcceptRuleSets { .. } | Stage::Ready(_) => 1,
        }
    }

    fn apply_event(self, event: HostEvent<'_>) -> Result<Self, UniqueFlightFillFailure> {
        match event {
            HostEvent::Bodies(bodies) => self.feed_bodies(bodies),
            HostEvent::FetchFailed { loaded, host } => self.advance_fetch_failed(loaded, host),
            HostEvent::Accepted { url } => self.push_rule_set_canonical(url),
        }
    }

    fn feed_bodies(self, bodies: &[&[u8]]) -> Result<Self, UniqueFlightFillFailure> {
        match self.stage {
            Stage::FetchSubscription(_) => self.feed_subscription(bodies),
            Stage::FetchConfig { .. } => self.feed_config(bodies),
            Stage::FetchRuleSets { .. } => self.feed_rule_set_prefix(bodies),
            Stage::AcceptRuleSets { .. } | Stage::Ready(_) => {
                Err(UniqueFlightFillFailure::Internal)
            }
        }
    }

    fn advance_fetch_failed(
        mut self,
        loaded: &[&[u8]],
        host: UniqueFlightHostFailure,
    ) -> Result<Self, UniqueFlightFillFailure> {
        match &self.stage {
            Stage::FetchSubscription(_) => {
                return match self.fail_subscription_prefix(loaded) {
                    UniqueFlightPrefix::Misaligned => Err(UniqueFlightFillFailure::Internal),
                    UniqueFlightPrefix::Continue => Err(UniqueFlightFillFailure::from_host(host)),
                    UniqueFlightPrefix::Error(error) => {
                        Err(UniqueFlightFillFailure::from_subscription(error))
                    }
                };
            }
            Stage::FetchConfig { .. } => {
                return Err(UniqueFlightFillFailure::from_host(host));
            }
            Stage::AcceptRuleSets { .. } | Stage::Ready(_) => {
                return Err(UniqueFlightFillFailure::Internal);
            }
            Stage::FetchRuleSets { .. } => {}
        }
        self.check_rule_set_prefix(loaded)?;
        Err(UniqueFlightFillFailure::from_host(host))
    }

    fn check_rule_set_prefix(&mut self, hop: &[&[u8]]) -> Result<(), UniqueFlightFillFailure> {
        let accounted = self.state.accounted_unique;
        let decoded_bytes = self.state.decoded_bytes;
        let cap = self.state.decoded_byte_cap;
        match &mut self.stage {
            Stage::FetchRuleSets { bound, loaded, .. } => {
                if accounted != loaded.len() {
                    return Err(UniqueFlightFillFailure::Internal);
                }
                let mut combined = loaded.iter().map(Vec::as_slice).collect::<Vec<_>>();
                combined.extend_from_slice(hop);
                bound
                    .check_loaded_prefix_with_decoded_budget(
                        &combined,
                        accounted,
                        decoded_bytes,
                        cap,
                    )
                    .map_err(UniqueFlightFillFailure::from_rule_set)
            }
            _ => Err(UniqueFlightFillFailure::Internal),
        }
    }

    fn feed_rule_set_prefix(mut self, hop: &[&[u8]]) -> Result<Self, UniqueFlightFillFailure> {
        self.check_rule_set_prefix(hop)?;
        let unique_count = match &self.stage {
            Stage::FetchRuleSets { unique_urls, .. } => unique_urls.len(),
            _ => return Err(UniqueFlightFillFailure::Internal),
        };
        self.state
            .credit_decoded(hop.iter().map(|body| body.len()))?;
        match &mut self.stage {
            Stage::FetchRuleSets { loaded, .. } => {
                loaded.extend(hop.iter().map(|body| body.to_vec()));
            }
            _ => return Err(UniqueFlightFillFailure::Internal),
        }
        self.state.accounted_unique = match &self.stage {
            Stage::FetchRuleSets { loaded, .. } => loaded.len(),
            _ => return Err(UniqueFlightFillFailure::Internal),
        };
        if self.state.accounted_unique == unique_count {
            self.finish_rule_sets()
        } else {
            Ok(self)
        }
    }

    fn push_rule_set_canonical(self, url: &str) -> Result<Self, UniqueFlightFillFailure> {
        let UniqueFlightSessionV1 { mut state, stage } = self;
        let Stage::AcceptRuleSets {
            prepared,
            mut fill,
            pending_url: _,
        } = stage
        else {
            return Err(UniqueFlightFillFailure::Internal);
        };
        if fill.occurrence_count() >= prepared.rule_set_requests().len() {
            return Err(UniqueFlightFillFailure::from_rule_set(
                Acl4SsrRenderError::RuleSetAlignment,
            ));
        }
        fill.push_remote(url);
        state.unique_remotes.remember(url);
        let next = prepared
            .next_rule_set_url(fill.occurrence_count())
            .map(str::to_owned);
        if let Some(pending_url) = next {
            Ok(Self {
                state,
                stage: Stage::AcceptRuleSets {
                    prepared,
                    fill,
                    pending_url,
                },
            })
        } else {
            let unique_urls = fill.unique_urls().to_vec();
            let bound = prepared
                .finish_rule_sets(fill)
                .map_err(UniqueFlightFillFailure::from_rule_set)?;
            state.accounted_unique = 0;
            if unique_urls.is_empty() {
                keep_pass_rule_sets(state, bound, &[])
            } else {
                Ok(Self {
                    state,
                    stage: Stage::FetchRuleSets {
                        bound,
                        unique_urls,
                        loaded: Vec::new(),
                    },
                })
            }
        }
    }

    fn fail_subscription_prefix(&self, loaded: &[&[u8]]) -> UniqueFlightPrefix {
        let failed_unique_index = loaded.len();
        let loaded = loaded.iter().copied().map(Some).collect::<Vec<_>>();
        match &self.stage {
            Stage::FetchSubscription(fill) => fill.prefix_error_before_unique_failure(
                &self.state.sources,
                &loaded,
                failed_unique_index,
            ),
            _ => UniqueFlightPrefix::Misaligned,
        }
    }

    fn feed_subscription(self, bodies: &[&[u8]]) -> Result<Self, UniqueFlightFillFailure> {
        let UniqueFlightSessionV1 { mut state, stage } = self;
        let Stage::FetchSubscription(fill) = stage else {
            return Err(UniqueFlightFillFailure::Internal);
        };
        if bodies.len() != fill.unique_urls().len() {
            return Err(UniqueFlightFillFailure::Internal);
        }
        let prepared = match fill.prepare_subscription(&state.sources, bodies) {
            None => return Err(UniqueFlightFillFailure::Internal),
            Some(Err(error)) => return Err(UniqueFlightFillFailure::from_subscription(error)),
            Some(Ok(prepared)) => prepared,
        };
        let Some(sizes) = fill.unique_decoded_bytes(&prepared) else {
            return Err(UniqueFlightFillFailure::Internal);
        };
        state.credit_decoded(sizes)?;
        state.accounted_unique = 0;
        Self {
            state,
            stage: Stage::FetchSubscription(fill),
        }
        .advance_after_subscription(prepared)
    }

    fn feed_config(self, bodies: &[&[u8]]) -> Result<Self, UniqueFlightFillFailure> {
        let UniqueFlightSessionV1 { mut state, stage } = self;
        let Stage::FetchConfig { prepared, fill } = stage else {
            return Err(UniqueFlightFillFailure::Internal);
        };
        if bodies.len() != fill.unique_urls().len() {
            return Err(UniqueFlightFillFailure::Internal);
        }
        let Some(body) = bodies.first().copied() else {
            return Err(UniqueFlightFillFailure::Internal);
        };
        let prepared = prepared
            .prepare_acl4ssr_config_v1(body)
            .map_err(UniqueFlightFillFailure::from_config)?;
        state.credit_decoded([body.len()])?;
        state.accounted_unique = 0;
        after_config(state, prepared)
    }

    fn advance_after_subscription(
        self,
        prepared: PreparedSubscriptionV1,
    ) -> Result<Self, UniqueFlightFillFailure> {
        let UniqueFlightSessionV1 {
            mut state,
            stage: _,
        } = self;
        match state.config_canonical.clone() {
            None => {
                let document = prepared
                    .render_builtin_v1(state.target)
                    .map_err(UniqueFlightFillFailure::from_render)?;
                Ok(Self {
                    state,
                    stage: Stage::Ready(document),
                })
            }
            Some(config) => {
                state.unique_remotes.remember(&config);
                Ok(Self {
                    state,
                    stage: Stage::FetchConfig {
                        prepared,
                        fill: UniqueFlightFillV1::bind_remote([config.as_str()]),
                    },
                })
            }
        }
    }

    fn finish_rule_sets(self) -> Result<Self, UniqueFlightFillFailure> {
        let UniqueFlightSessionV1 { state, stage } = self;
        let Stage::FetchRuleSets { bound, loaded, .. } = stage else {
            return Err(UniqueFlightFillFailure::Internal);
        };
        let bodies = loaded.iter().map(Vec::as_slice).collect::<Vec<_>>();
        keep_pass_rule_sets(state, bound, &bodies)
    }
}

fn after_config(
    state: SessionState,
    prepared: PreparedAcl4SsrV1,
) -> Result<UniqueFlightSessionV1, UniqueFlightFillFailure> {
    if prepared.rule_set_requests().is_empty() {
        let bound = prepared
            .finish_rule_sets(UniqueFlightFillV1::empty())
            .map_err(UniqueFlightFillFailure::from_rule_set)?;
        return keep_pass_rule_sets(state, bound, &[]);
    }
    let pending_url = prepared
        .next_rule_set_url(0)
        .ok_or(UniqueFlightFillFailure::Internal)?
        .to_owned();
    Ok(UniqueFlightSessionV1 {
        state,
        stage: Stage::AcceptRuleSets {
            prepared,
            fill: UniqueFlightFillV1::empty(),
            pending_url,
        },
    })
}

fn keep_pass_rule_sets(
    state: SessionState,
    bound: PreparedAcl4SsrRuleSetsV1,
    bodies: &[&[u8]],
) -> Result<UniqueFlightSessionV1, UniqueFlightFillFailure> {
    let document = bound
        .render_v1(state.target, bodies)
        .map_err(UniqueFlightFillFailure::from_rule_set)?;
    Ok(UniqueFlightSessionV1 {
        state,
        stage: Stage::Ready(document),
    })
}

impl SessionState {
    fn credit_decoded(
        &mut self,
        sizes: impl IntoIterator<Item = usize>,
    ) -> Result<(), UniqueFlightFillFailure> {
        for size in sizes {
            let Some(sum) = self.decoded_bytes.checked_add(size) else {
                return Err(UniqueFlightFillFailure::ConversionLimit);
            };
            if sum > self.decoded_byte_cap {
                return Err(UniqueFlightFillFailure::ConversionLimit);
            }
            self.decoded_bytes = sum;
        }
        Ok(())
    }
}

impl UniqueFlightOutbound {
    #[must_use]
    pub fn url(&self) -> &str {
        match &self.session.stage {
            Stage::AcceptRuleSets { pending_url, .. } => pending_url.as_str(),
            _ => "",
        }
    }

    /// Session-wide first-seen Unique remotes if `accepted` is bound.
    ///
    /// Counts subscription, Config, and Rule Set identities together. Part of
    /// Outbound accept.
    #[must_use]
    pub fn unique_reservation(&self, accepted: &str) -> usize {
        match self.session.stage {
            Stage::AcceptRuleSets { .. } => {
                self.session.state.unique_remotes.count_if_push(accepted)
            }
            _ => 0,
        }
    }

    #[must_use]
    pub fn fulfill(self, accepted: &str) -> UniqueFlightDrive {
        if !matches!(self.session.stage, Stage::AcceptRuleSets { .. }) {
            return UniqueFlightDrive::Ended(Err(UniqueFlightFillFailure::Internal));
        }
        match self
            .session
            .apply_event(HostEvent::Accepted { url: accepted })
        {
            Ok(session) => session.into_drive(),
            Err(failure) => UniqueFlightDrive::Ended(Err(failure)),
        }
    }

    /// Host closed failure of Outbound accept. Does not push the URL.
    #[must_use]
    pub fn reject(self, host: UniqueFlightHostFailure) -> UniqueFlightDrive {
        if !matches!(self.session.stage, Stage::AcceptRuleSets { .. }) {
            return UniqueFlightDrive::Ended(Err(UniqueFlightFillFailure::Internal));
        }
        UniqueFlightDrive::Ended(Err(UniqueFlightFillFailure::from_host(host)))
    }
}

impl UniqueFlightFetch {
    /// Leftover first-seen canonical URLs. Session budget preflight stays here.
    #[must_use]
    pub fn urls(&self) -> &[String] {
        self.session.fetch_urls()
    }

    #[must_use]
    pub fn max_body_bytes(&self) -> usize {
        self.session.fetch_max_body_bytes()
    }

    #[must_use]
    pub fn capture_subscription_user_info(&self) -> bool {
        self.session.fetch_capture_subscription_user_info()
    }

    #[must_use]
    pub fn take_count(&self, session_concurrency: usize) -> usize {
        self.session.fetch_take_count(session_concurrency)
    }

    #[must_use]
    pub fn fulfill(self, bodies: UniqueFlightBodies<'_>) -> UniqueFlightDrive {
        if matches!(
            self.session.stage,
            Stage::AcceptRuleSets { .. } | Stage::Ready(_)
        ) {
            return UniqueFlightDrive::Ended(Err(UniqueFlightFillFailure::Internal));
        }
        let event = match bodies {
            UniqueFlightBodies::Complete(bodies) => HostEvent::Bodies(bodies),
            UniqueFlightBodies::Failed { loaded, host } => HostEvent::FetchFailed { loaded, host },
        };
        match self.session.apply_event(event) {
            Ok(session) => session.into_drive(),
            Err(failure) => UniqueFlightDrive::Ended(Err(failure)),
        }
    }
}

impl fmt::Debug for UniqueFlightSessionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UniqueFlightSessionV1")
            .field("source_count", &self.state.sources.len())
            .field("has_config", &self.state.config_canonical.is_some())
            .field("unique_remote_count", &self.state.unique_remotes.len())
            .field("target", &self.state.target)
            .field("decoded_bytes", &self.state.decoded_bytes)
            .field("decoded_byte_cap", &self.state.decoded_byte_cap)
            .field("accounted_unique", &self.state.accounted_unique)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for UniqueFlightDrive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Need(need) => match need.as_ref() {
                UniqueFlightNeed::Outbound(_) => formatter.write_str("Need(Outbound)"),
                UniqueFlightNeed::Fetch(_) => formatter.write_str("Need(Fetch)"),
            },
            Self::Ended(Ok(_)) => formatter.write_str("Ended(document)"),
            Self::Ended(Err(failure)) => formatter.debug_tuple("Ended").field(failure).finish(),
        }
    }
}

impl fmt::Debug for UniqueFlightNeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Outbound(_) => formatter.write_str("Outbound"),
            Self::Fetch(_) => formatter.write_str("Fetch"),
        }
    }
}

impl fmt::Debug for UniqueFlightOutbound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UniqueFlightOutbound")
            .field("session", &self.session)
            .finish()
    }
}

impl fmt::Debug for UniqueFlightFetch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UniqueFlightFetch")
            .field("session", &self.session)
            .finish()
    }
}

impl fmt::Debug for UniqueFlightBodies<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete(bodies) => formatter
                .debug_struct("Complete")
                .field("unique_count", &bodies.len())
                .finish(),
            Self::Failed { loaded, host } => formatter
                .debug_struct("Failed")
                .field("loaded_count", &loaded.len())
                .field("host", host)
                .finish(),
        }
    }
}

impl fmt::Display for UniqueFlightFillFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => formatter.write_str("invalid unique-flight input"),
            Self::ConversionLimit => formatter.write_str("resource limit exceeded"),
            Self::RemoteFailure => formatter.write_str("remote unique-flight failed"),
            Self::RemoteTimeout => formatter.write_str("remote unique-flight timed out"),
            Self::NoValidNodes { .. } => formatter.write_str("no valid nodes"),
            Self::Internal => formatter.write_str("unique-flight session is misaligned"),
        }
    }
}

impl std::error::Error for UniqueFlightFillFailure {}
