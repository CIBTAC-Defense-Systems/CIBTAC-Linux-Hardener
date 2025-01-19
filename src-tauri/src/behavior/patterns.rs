pub struct PatternMatcher {
    patterns: HashMap<String, BehaviorPattern>,
    active_sequences: Vec<ActiveSequence>,
    correlation_engine: CorrelationEngine,
}

#[derive(Debug, Clone)]
pub struct BehaviorPattern {
    pub id: String,
    pub sequence: Vec<EventMatcher>,
    pub timeframe: Duration,
    pub conditions: Vec<PatternCondition>,
    pub severity: ThreatLevel,
}

#[derive(Debug)]
struct ActiveSequence {
    pattern_id: String,
    matched_events: Vec<SystemEvent>,
    start_time: Instant,
    current_state: usize,
}

#[derive(Debug)]
pub struct CorrelationEngine {
    window_size: Duration,
    recent_events: VecDeque<SystemEvent>,
    correlation_rules: Vec<CorrelationRule>,
}

#[derive(Debug)]
pub struct CorrelationRule {
    rule_id: String,
    event_types: Vec<EventType>,
    condition: Box<dyn Fn(&[SystemEvent]) -> bool + Send + Sync>,
    timeframe: Duration,
}

impl PatternMatcher {
    pub fn new() -> Self {
        Self {
            patterns: HashMap::new(),
            active_sequences: Vec::new(),
            correlation_engine: CorrelationEngine::new(),
        }
    }

    pub async fn match_event(
        &mut self,
        event: &SystemEvent,
    ) -> Result<Option<Vec<BehaviorPattern>>, BehaviorError> {
        // Update active sequences and remove expired ones
        self.update_active_sequences(event).await?;

        // Check for new pattern matches
        let mut matched_patterns = Vec::new();
        for pattern in self.patterns.values() {
            if self.starts_new_sequence(pattern, event) {
                self.start_sequence(pattern.id.clone(), event.clone());
            }

            if let Some(sequence) = self.find_matching_sequence(pattern, event) {
                if self.verify_pattern_conditions(pattern, &sequence).await? {
                    matched_patterns.push(pattern.clone());
                }
            }
        }

        // Update correlation engine
        self.correlation_engine.process_event(event).await?;

        if matched_patterns.is_empty() {
            Ok(None)
        } else {
            Ok(Some(matched_patterns))
        }
    }

    async fn verify_pattern_conditions(
        &self,
        pattern: &BehaviorPattern,
        sequence: &ActiveSequence,
    ) -> Result<bool, BehaviorError> {
        for condition in &pattern.conditions {
            match condition {
                PatternCondition::Timeframe(duration) => {
                    if sequence.start_time.elapsed() > *duration {
                        return Ok(false);
                    }
                }
                PatternCondition::Frequency { count, window } => {
                    if !self
                        .check_frequency_condition(sequence, *count, *window)
                        .await?
                    {
                        return Ok(false);
                    }
                }
                PatternCondition::Custom(checker) => {
                    if !checker(&sequence.matched_events) {
                        return Ok(false);
                    }
                }
                // Add more condition types as needed
            }
        }
        Ok(true)
    }

    pub async fn add_pattern(&mut self, pattern: BehaviorPattern) -> Result<(), BehaviorError> {
        // Validate pattern before adding
        self.validate_pattern(&pattern)?;

        self.patterns.insert(pattern.id.clone(), pattern);
        Ok(())
    }

    pub async fn update_patterns(
        &mut self,
        new_patterns: Vec<BehaviorPattern>,
    ) -> Result<(), BehaviorError> {
        for pattern in new_patterns {
            self.add_pattern(pattern).await?;
        }
        Ok(())
    }

    pub async fn analyze_sequence(
        &self,
        events: &[SystemEvent],
    ) -> Result<Vec<CorrelationMatch>, BehaviorError> {
        self.correlation_engine.analyze_sequence(events).await
    }
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self {
            window_size: Duration::from_secs(3600), // 1 hour default
            recent_events: VecDeque::new(),
            correlation_rules: Vec::new(),
        }
    }

    pub async fn process_event(&mut self, event: &SystemEvent) -> Result<(), BehaviorError> {
        // Add event to recent events
        self.recent_events.push_back(event.clone());

        // Remove events outside the window
        while let Some(old_event) = self.recent_events.front() {
            if event.timestamp.duration_since(old_event.timestamp)? > self.window_size {
                self.recent_events.pop_front();
            } else {
                break;
            }
        }

        // Check correlation rules
        for rule in &self.correlation_rules {
            if self.check_rule(rule)? {
                // Emit correlation event
                // This could be enhanced to emit through a channel
            }
        }

        Ok(())
    }

    pub async fn analyze_sequence(
        &self,
        events: &[SystemEvent],
    ) -> Result<Vec<CorrelationMatch>, BehaviorError> {
        let mut matches = Vec::new();

        for rule in &self.correlation_rules {
            if self.matches_rule(events, rule)? {
                matches.push(CorrelationMatch {
                    rule_id: rule.rule_id.clone(),
                    matched_events: events.to_vec(),
                    timestamp: SystemTime::now(),
                });
            }
        }

        Ok(matches)
    }

    fn matches_rule(
        &self,
        events: &[SystemEvent],
        rule: &CorrelationRule,
    ) -> Result<bool, BehaviorError> {
        // Check if events match the rule's event types in sequence
        if !self.match_event_sequence(events, &rule.event_types)? {
            return Ok(false);
        }

        // Check timeframe
        if !self.check_timeframe(events, rule.timeframe)? {
            return Ok(false);
        }

        // Apply rule condition
        Ok((rule.condition)(events))
    }

    fn match_event_sequence(
        &self,
        events: &[SystemEvent],
        types: &[EventType],
    ) -> Result<bool, BehaviorError> {
        if events.len() < types.len() {
            return Ok(false);
        }

        for (event, expected_type) in events.iter().zip(types.iter()) {
            if event.event_type != *expected_type {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn check_timeframe(
        &self,
        events: &[SystemEvent],
        timeframe: Duration,
    ) -> Result<bool, BehaviorError> {
        if events.is_empty() {
            return Ok(true);
        }

        let first = events.first().unwrap();
        let last = events.last().unwrap();

        Ok(last.timestamp.duration_since(first.timestamp)? <= timeframe)
    }
}
