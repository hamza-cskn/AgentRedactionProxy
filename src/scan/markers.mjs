// Every restorable marker: [REDACTED_<TYPE>_<32 hex>]. IP markers share the schema.
export const RESTORABLE_MARKER_SOURCE = '\\[REDACTED_(?:IP|TEXT|API_KEY|JWT|PRIVATE_KEY|PASSWORD)_[a-f0-9]{32}\\]';
