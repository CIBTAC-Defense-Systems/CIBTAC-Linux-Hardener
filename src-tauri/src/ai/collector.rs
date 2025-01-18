pub struct DataCollector {
    storage: Arc<RwLock<DataStorage>>,
    config: CollectorConfig,
}

impl DataCollector {
    pub async fn store_interaction(
        &mut self,
        event: &SecurityEvent,
        prompt: &str,
        response: &str,
    ) -> Result<(), LLMError> {
        let interaction = SecurityInteraction {
            timestamp: Utc::now(),
            event: event.clone(),
            prompt: prompt.to_string(),
            response: response.to_string(),
            metadata: self.gather_metadata().await?,
        };

        self.storage.write().await.store(interaction).await?;
        Ok(())
    }
}
