import { POOL_SIZE, Redactor } from './redactor.mjs';
import { customTextMatcher } from './scan/custom-text.mjs';
import { transformJsonText } from './scan/traverse.mjs';
import { validateSensitiveTexts } from './sensitive-texts.mjs';
import { StateStore, defaultStatePath, readState } from './store.mjs';

export { MappingCapacityError, emptyState, validateState } from './redactor.mjs';
export { defaultStatePath } from './store.mjs';

export class TransformedBodyLimitError extends Error {
  constructor() {
    super('Transformed body exceeds configured limit');
    this.code = 'TRANSFORMED_BODY_TOO_LARGE';
  }
}

// What the proxy talks to: each operation runs a Redactor on a fresh state
// snapshot inside a StateStore transaction. state and realToFake expose the
// last committed snapshot, read-only.
export class MappingStore {
  static async status(statePath = defaultStatePath(), { encryptionKey } = {}) {
    const state = await readState(statePath, encryptionKey);
    return { used: state.nextIndex, capacity: POOL_SIZE, remaining: POOL_SIZE - state.nextIndex };
  }

  static async open(statePath = defaultStatePath(), { sensitiveTexts = [], encryptionKey, storageGuard } = {}) {
    const customText = customTextMatcher(validateSensitiveTexts(sensitiveTexts));
    const { store, state } = await StateStore.open(statePath, { encryptionKey, storageGuard });
    return new MappingStore(store, new Redactor(state, customText), customText);
  }

  constructor(store, redactor, customText) {
    this.store = store;
    this.redactor = redactor;
    this.customText = customText;
  }

  get statePath() { return this.store.statePath; }
  get state() { return this.redactor.state; }
  get realToFake() { return this.redactor.realToFake; }

  obfuscate(text, { maxBytes = Number.POSITIVE_INFINITY, redact = false, mode, redactionLimits } = {}) {
    let redactor;
    const operation = this.store.update((state) => {
      redactor = new Redactor(state, this.customText);
      const { secretCount, ...transformed } = redactor.redact(text, { secrets: redact, mode, redactionLimits });
      if (Buffer.byteLength(transformed.body, 'utf8') > maxBytes) throw new TransformedBodyLimitError();
      return { value: redact ? { ...transformed, secretCount } : transformed, state: redactor.changed ? redactor.state : null };
    });
    return operation.then((value) => {
      this.redactor = redactor;
      return value;
    }, (error) => {
      // The rename is already committed when directory syncing fails.
      if (error.code === 'MAPPING_DURABILITY_FAILED') this.redactor = redactor;
      throw error;
    });
  }

  obfuscateRequest(text, options = {}) {
    return this.obfuscate(text, { ...options, redact: true });
  }

  containsSensitiveTexts(text) {
    return transformJsonText(text, (value) => ({ body: value, count: this.customText(value).length })).count > 0;
  }

  deobfuscate(text) {
    return this.deobfuscateMany([text]).then(([result]) => result);
  }

  deobfuscateMany(texts) {
    return this.store.read((state) => {
      this.redactor = new Redactor(state, this.customText);
      return texts.map((text) => this.redactor.restore(text));
    });
  }
}
