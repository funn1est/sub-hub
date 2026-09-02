use std::fmt;

use url::Url;

use super::table::{SessionUrlIndex, UniqueFlightPrepare, UniqueUrls};
use super::{UniqueFlightFillV1, UniqueFlightPrefix};
use crate::{
    Acl4SsrPreparationError, Acl4SsrRenderError, ConversionRenderError, MAX_CONFIG_BYTES,
    MAX_RULE_SET_BYTES, MAX_SUBSCRIPTION_INPUT_BYTES, OutputTarget, PreparedAcl4SsrRuleSetsV1,
    PreparedAcl4SsrV1, PreparedSubscriptionV1, RenderedConfig, SkipCountsV1,
    SubscriptionPreparationError, subscription_prepare::RemoteSourceFailureV1,
};

/// Unique-flight fill session: bind → fill → prefix / grammar-beats-budget →
/// prepare / decoded accounts → Keep-pass.
pub struct UniqueFlightSessionV1 {
    state: SessionState,
    stage: Stage,
}

struct SessionState {
    sources: Vec<String>,
    config_canonical: Option<Url>,
    /// Session-wide first-seen Unique remotes. Fill plans index into this ledger.
    unique_remotes: UniqueUrls,
    unique_remote_cap: usize,
    target: OutputTarget,
    decoded_byte_cap: usize,
    decoded_bytes: usize,
    append_subscription_user_info: bool,
    expand: bool,
}

enum Stage {
    FetchSubscription(UniqueFlightFillV1),
    FetchConfig {
        prepared: PreparedSubscriptionV1,
        fill: UniqueFlightFillV1,
    },
    FetchRuleSets(RuleSetFetch),
    Ready(RenderedConfig),
}

struct RuleSetFetch {
    bound: PreparedAcl4SsrRuleSetsV1,
    loaded: Vec<Vec<u8>>,
}

/// Move-only Unique-flight fill progress. HTTP drives [`Self::Fetch`].
pub enum UniqueFlightDrive {
    Fetch(UniqueFlightFetch),
    Ended(Result<RenderedConfig, UniqueFlightFillFailure>),
}

/// One unique fetch. Leftover first-seen count stays on [`UniqueFlightFetchPlan`]
/// so Session budget attempt preflight does not name the resource kind.
pub struct UniqueFlightFetch {
    session: Box<UniqueFlightSessionV1>,
}

/// Hop HTTP should fetch now, plus leftover count for attempt preflight.
pub struct UniqueFlightFetchPlan<'a> {
    ledger: &'a UniqueUrls,
    url_indices: &'a [SessionUrlIndex],
    pub leftover_count: usize,
    pub max_body_bytes: usize,
    pub capture_subscription_user_info: bool,
}

impl UniqueFlightFetchPlan<'_> {
    /// First-seen hop URLs for this take, in fetch order. Indices came from this ledger.
    #[must_use]
    pub fn urls(&self) -> impl ExactSizeIterator<Item = &Url> + '_ {
        self.url_indices
            .iter()
            .map(|&ledger_index| self.ledger.url(ledger_index))
    }
}

/// Unique bodies HTTP returns after a fetch hop.
#[derive(Clone)]
pub enum UniqueFlightBodies {
    Complete(Vec<Vec<u8>>),
    Failed {
        loaded: Vec<Vec<u8>>,
        host: UniqueFlightHostFailure,
    },
}

/// Closed host fetch outcome when a unique hop fails. Session maps this into
/// [`UniqueFlightFillFailure`] unless a loaded prefix already beats it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UniqueFlightHostFailure {
    Failure,
    Timeout,
    /// Outbound accept rejected the URL (policy or port).
    Rejected,
}

/// Closed Unique-flight fill failure. HTTP maps this onto GET once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UniqueFlightFillFailure {
    InvalidInput,
    InvalidRemoteContent,
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
            SubscriptionPreparationError::RemoteFailure { reason, .. } => {
                match reason {
                    RemoteSourceFailureV1::InputTooLarge
                    | RemoteSourceFailureV1::DecodedTooLarge => Self::ConversionLimit,
                    RemoteSourceFailureV1::InvalidUtf8
                    | RemoteSourceFailureV1::InvalidLineEnding => Self::InvalidRemoteContent,
                }
            }
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
            UniqueFlightHostFailure::Rejected => Self::InvalidInput,
        }
    }
}

impl UniqueFlightSessionV1 {
    /// Bind subscription occurrences. Config is one Unique flight on the same plan.
    ///
    /// `decoded_byte_cap` and `unique_remote_cap` are Session budget caps. The
    /// session owns both running tallies and whether the subscription hop may
    /// capture Subscription user-info; HTTP does not feed counts per step.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn start<'a, I>(
        sources: &[String],
        occurrence_canonical: I,
        config_canonical: Option<&Url>,
        target: OutputTarget,
        decoded_byte_cap: usize,
        unique_remote_cap: usize,
        append_subscription_user_info: bool,
        expand: bool,
    ) -> UniqueFlightDrive
    where
        I: IntoIterator<Item = Option<&'a Url>>,
    {
        match Self::bind(
            sources,
            occurrence_canonical,
            config_canonical,
            target,
            decoded_byte_cap,
            unique_remote_cap,
            append_subscription_user_info,
            expand,
        ) {
            Ok(session) => session.into_drive(),
            Err(failure) => UniqueFlightDrive::Ended(Err(failure)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn bind<'a, I>(
        sources: &[String],
        occurrence_canonical: I,
        config_canonical: Option<&Url>,
        target: OutputTarget,
        decoded_byte_cap: usize,
        unique_remote_cap: usize,
        append_subscription_user_info: bool,
        expand: bool,
    ) -> Result<Self, UniqueFlightFillFailure>
    where
        I: IntoIterator<Item = Option<&'a Url>>,
    {
        let mut unique_remotes = UniqueUrls::empty();
        let fetch_subscriptions = expand || !target.unexpands_subscriptions();
        let fill = if fetch_subscriptions {
            UniqueFlightFillV1::try_bind_optional(
                &mut unique_remotes,
                unique_remote_cap,
                occurrence_canonical,
            )
            .map_err(|()| UniqueFlightFillFailure::ConversionLimit)?
        } else {
            UniqueFlightFillV1::try_bind_optional(
                &mut unique_remotes,
                unique_remote_cap,
                occurrence_canonical.into_iter().map(|_| None),
            )
            .map_err(|()| UniqueFlightFillFailure::ConversionLimit)?
        };
        let empty_uniques = unique_remotes.is_empty();
        let state = SessionState {
            sources: sources.to_vec(),
            config_canonical: config_canonical.cloned(),
            unique_remotes,
            unique_remote_cap,
            target,
            decoded_byte_cap,
            decoded_bytes: 0,
            append_subscription_user_info,
            expand,
        };
        if empty_uniques {
            Self::feed_subscription(state, &fill, &[])
        } else {
            Ok(Self {
                state,
                stage: Stage::FetchSubscription(fill),
            })
        }
    }

    fn into_drive(self) -> UniqueFlightDrive {
        match self.stage {
            Stage::Ready(document) => UniqueFlightDrive::Ended(Ok(document)),
            Stage::FetchSubscription(_) | Stage::FetchConfig { .. } | Stage::FetchRuleSets(_) => {
                UniqueFlightDrive::Fetch(UniqueFlightFetch {
                    session: Box::new(self),
                })
            }
        }
    }

    fn fetch_url_indices(&self) -> &[SessionUrlIndex] {
        match &self.stage {
            Stage::FetchSubscription(fill) | Stage::FetchConfig { fill, .. } => {
                fill.stage_unique_indices()
            }
            Stage::FetchRuleSets(fetch) => fetch.remaining_unique_indices(),
            Stage::Ready(_) => &[],
        }
    }

    fn fetch_max_body_bytes(&self) -> usize {
        match self.stage {
            Stage::FetchSubscription(_) => MAX_SUBSCRIPTION_INPUT_BYTES,
            Stage::FetchConfig { .. } => MAX_CONFIG_BYTES,
            Stage::FetchRuleSets(_) => MAX_RULE_SET_BYTES,
            Stage::Ready(_) => 0,
        }
    }

    fn fetch_capture_subscription_user_info(&self) -> bool {
        match &self.stage {
            Stage::FetchSubscription(fill) => {
                self.state.append_subscription_user_info
                    && self.state.sources.len() == 1
                    && fill.flight_count() == 1
            }
            _ => false,
        }
    }

    fn fetch_take_count(&self, session_concurrency: usize) -> usize {
        let n = self.fetch_url_indices().len();
        match self.stage {
            Stage::FetchSubscription(_) => n,
            Stage::FetchRuleSets(_) => session_concurrency.min(n),
            Stage::FetchConfig { .. } | Stage::Ready(_) => n.min(1),
        }
    }

    fn feed<F>(self, bodies: &[Vec<u8>], accept: &mut F) -> Result<Self, UniqueFlightFillFailure>
    where
        F: FnMut(&str) -> Result<Url, UniqueFlightHostFailure>,
    {
        let UniqueFlightSessionV1 { state, stage } = self;
        match stage {
            Stage::FetchSubscription(fill) => Self::feed_subscription(state, &fill, bodies),
            Stage::FetchConfig { prepared, fill } => {
                Self::feed_config(state, prepared, &fill, bodies, accept)
            }
            Stage::FetchRuleSets(fetch) => Self::feed_rule_sets(state, fetch, bodies),
            Stage::Ready(_) => Err(UniqueFlightFillFailure::Internal),
        }
    }

    fn feed_config<F>(
        mut state: SessionState,
        prepared: PreparedSubscriptionV1,
        fill: &UniqueFlightFillV1,
        bodies: &[Vec<u8>],
        accept: &mut F,
    ) -> Result<Self, UniqueFlightFillFailure>
    where
        F: FnMut(&str) -> Result<Url, UniqueFlightHostFailure>,
    {
        if bodies.len() != fill.flight_count() {
            return Err(UniqueFlightFillFailure::Internal);
        }
        let Some(body) = bodies.first() else {
            return Err(UniqueFlightFillFailure::Internal);
        };
        let prepared = prepared
            .prepare_acl4ssr_config_v1(body)
            .map_err(UniqueFlightFillFailure::from_config)?;
        state.credit_decoded([body.len()])?;
        after_config(state, prepared, accept)
    }

    fn advance_fetch_failed(
        self,
        loaded: &[Vec<u8>],
        host: UniqueFlightHostFailure,
    ) -> Result<Self, UniqueFlightFillFailure> {
        let UniqueFlightSessionV1 { state, mut stage } = self;
        match &mut stage {
            Stage::FetchSubscription(fill) => {
                match fail_subscription_prefix(fill, &state.sources, loaded) {
                    UniqueFlightPrefix::Misaligned => Err(UniqueFlightFillFailure::Internal),
                    UniqueFlightPrefix::Continue => Err(UniqueFlightFillFailure::from_host(host)),
                    UniqueFlightPrefix::Error(error) => {
                        Err(UniqueFlightFillFailure::from_subscription(error))
                    }
                }
            }
            Stage::FetchConfig { .. } => Err(UniqueFlightFillFailure::from_host(host)),
            Stage::Ready(_) => Err(UniqueFlightFillFailure::Internal),
            Stage::FetchRuleSets(fetch) => {
                fetch.check_hop(loaded, state.decoded_bytes, state.decoded_byte_cap)?;
                Err(UniqueFlightFillFailure::from_host(host))
            }
        }
    }

    fn feed_rule_sets(
        mut state: SessionState,
        mut fetch: RuleSetFetch,
        hop: &[Vec<u8>],
    ) -> Result<Self, UniqueFlightFillFailure> {
        fetch.check_hop(hop, state.decoded_bytes, state.decoded_byte_cap)?;
        let unique_count = fetch.unique_count();
        state.credit_decoded(hop.iter().map(Vec::len))?;
        fetch.loaded.extend(hop.iter().cloned());
        if fetch.loaded.len() == unique_count {
            return keep_pass_loaded_rule_sets(state, fetch);
        }
        Ok(Self {
            state,
            stage: Stage::FetchRuleSets(fetch),
        })
    }

    fn feed_subscription(
        mut state: SessionState,
        fill: &UniqueFlightFillV1,
        bodies: &[Vec<u8>],
    ) -> Result<Self, UniqueFlightFillFailure> {
        if bodies.len() != fill.flight_count() {
            return Err(UniqueFlightFillFailure::Internal);
        }
        let prepared = match fill.prepare_subscription(&state.sources, bodies) {
            UniqueFlightPrepare::Misaligned => {
                return Err(UniqueFlightFillFailure::Internal);
            }
            UniqueFlightPrepare::Failed(error) => {
                return Err(UniqueFlightFillFailure::from_subscription(error));
            }
            UniqueFlightPrepare::Ready(prepared) => prepared,
        };
        let Some(sizes) = fill.unique_decoded_bytes(&prepared) else {
            return Err(UniqueFlightFillFailure::Internal);
        };
        state.credit_decoded(sizes)?;
        Self::advance_after_subscription(state, prepared)
    }

    fn advance_after_subscription(
        mut state: SessionState,
        prepared: PreparedSubscriptionV1,
    ) -> Result<Self, UniqueFlightFillFailure> {
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
                let mut fill = UniqueFlightFillV1::empty();
                state.commit_remote(&mut fill, &config)?;
                Ok(Self {
                    state,
                    stage: Stage::FetchConfig { prepared, fill },
                })
            }
        }
    }
}

fn fail_subscription_prefix(
    fill: &UniqueFlightFillV1,
    sources: &[String],
    loaded: &[Vec<u8>],
) -> UniqueFlightPrefix {
    let failed_unique_index = loaded.len();
    let loaded: Vec<Option<&[u8]>> = loaded.iter().map(|body| Some(body.as_slice())).collect();
    fill.prefix_error_before_unique_failure(sources, &loaded, failed_unique_index)
}

impl RuleSetFetch {
    fn remaining_unique_indices(&self) -> &[SessionUrlIndex] {
        self.bound.remaining_unique_indices(self.loaded.len())
    }

    fn unique_count(&self) -> usize {
        self.bound.unique_flight_count()
    }

    fn check_hop(
        &mut self,
        hop: &[Vec<u8>],
        decoded_bytes: usize,
        cap: usize,
    ) -> Result<(), UniqueFlightFillFailure> {
        let accounted = self.loaded.len();
        let mut combined = self.loaded.iter().map(Vec::as_slice).collect::<Vec<_>>();
        combined.extend(hop.iter().map(Vec::as_slice));
        self.bound
            .check_loaded_prefix_with_decoded_budget(&combined, accounted, decoded_bytes, cap)
            .map_err(UniqueFlightFillFailure::from_rule_set)
    }
}

fn after_config<F>(
    mut state: SessionState,
    prepared: PreparedAcl4SsrV1,
    accept: &mut F,
) -> Result<UniqueFlightSessionV1, UniqueFlightFillFailure>
where
    F: FnMut(&str) -> Result<Url, UniqueFlightHostFailure>,
{
    if prepared.rule_set_requests().is_empty() {
        let bound = prepared
            .finish_rule_sets(UniqueFlightFillV1::empty())
            .map_err(UniqueFlightFillFailure::from_rule_set)?;
        return keep_pass_rule_sets(state, bound, &[]);
    }
    if !state.expand && state.target.unexpands_rule_sets() {
        return keep_pass_unexpanded_acl4ssr(state, prepared);
    }
    let mut fill = UniqueFlightFillV1::empty();
    for request in prepared.rule_set_requests() {
        let accepted = accept(request.url()).map_err(UniqueFlightFillFailure::from_host)?;
        state.commit_remote(&mut fill, &accepted)?;
    }
    let needs_fetch = fill.flight_count() > 0;
    let bound = prepared
        .finish_rule_sets(fill)
        .map_err(UniqueFlightFillFailure::from_rule_set)?;
    if needs_fetch {
        Ok(UniqueFlightSessionV1 {
            state,
            stage: Stage::FetchRuleSets(RuleSetFetch {
                bound,
                loaded: Vec::new(),
            }),
        })
    } else {
        keep_pass_rule_sets(state, bound, &[])
    }
}

fn keep_pass_unexpanded_acl4ssr(
    state: SessionState,
    prepared: PreparedAcl4SsrV1,
) -> Result<UniqueFlightSessionV1, UniqueFlightFillFailure> {
    let document = prepared
        .render_unexpanded_v1(state.target)
        .map_err(UniqueFlightFillFailure::from_rule_set)?;
    Ok(UniqueFlightSessionV1 {
        state,
        stage: Stage::Ready(document),
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

fn keep_pass_loaded_rule_sets(
    state: SessionState,
    fetch: RuleSetFetch,
) -> Result<UniqueFlightSessionV1, UniqueFlightFillFailure> {
    let bodies = fetch.loaded.iter().map(Vec::as_slice).collect::<Vec<_>>();
    keep_pass_rule_sets(state, fetch.bound, &bodies)
}

impl SessionState {
    fn commit_remote(
        &mut self,
        fill: &mut UniqueFlightFillV1,
        url: &Url,
    ) -> Result<(), UniqueFlightFillFailure> {
        let session_index = self
            .unique_remotes
            .try_insert(url, self.unique_remote_cap)
            .map_err(|()| UniqueFlightFillFailure::ConversionLimit)?;
        fill.push_session_index(session_index);
        Ok(())
    }

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

impl UniqueFlightFetch {
    #[must_use]
    pub fn plan(&self, session_concurrency: usize) -> UniqueFlightFetchPlan<'_> {
        let indices = self.session.fetch_url_indices();
        let take = self
            .session
            .fetch_take_count(session_concurrency)
            .min(indices.len());
        UniqueFlightFetchPlan {
            ledger: &self.session.state.unique_remotes,
            url_indices: indices.get(..take).unwrap_or(&[]),
            leftover_count: indices.len(),
            max_body_bytes: self.session.fetch_max_body_bytes(),
            capture_subscription_user_info: self.session.fetch_capture_subscription_user_info(),
        }
    }

    /// Completes this hop. HTTP always supplies `accept_outbound`; the session
    /// calls it only when the hop still needs Outbound accept.
    #[must_use]
    pub fn fulfill(
        self,
        bodies: UniqueFlightBodies,
        mut accept_outbound: impl FnMut(&str) -> Result<Url, UniqueFlightHostFailure>,
    ) -> UniqueFlightDrive {
        let result = match bodies {
            UniqueFlightBodies::Complete(bodies) => {
                self.session.feed(&bodies, &mut accept_outbound)
            }
            UniqueFlightBodies::Failed { loaded, host } => {
                self.session.advance_fetch_failed(&loaded, host)
            }
        };
        match result {
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
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for UniqueFlightDrive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fetch(_) => formatter.write_str("Fetch"),
            Self::Ended(Ok(_)) => formatter.write_str("Ended(document)"),
            Self::Ended(Err(failure)) => formatter.debug_tuple("Ended").field(failure).finish(),
        }
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

impl fmt::Debug for UniqueFlightBodies {
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
            Self::InvalidRemoteContent => {
                formatter.write_str("invalid remote unique-flight content")
            }
            Self::ConversionLimit => formatter.write_str("resource limit exceeded"),
            Self::RemoteFailure => formatter.write_str("remote unique-flight failed"),
            Self::RemoteTimeout => formatter.write_str("remote unique-flight timed out"),
            Self::NoValidNodes { .. } => formatter.write_str("no valid nodes"),
            Self::Internal => formatter.write_str("unique-flight session is misaligned"),
        }
    }
}

impl std::error::Error for UniqueFlightFillFailure {}
