package dev.cyberstamp.sigmund.core;

/**
 * The key-fetching settings {@link Sigmund.Builder} passes to OpenPGP tools from the
 * {@code verification} section.
 * <p>
 * They reach the tool in its settings map but are never written under {@code tools}, so no
 * factory lists them in {@link SignatureToolFactory#acceptedSettings()}.
 */
enum FetchSetting implements ToolSetting {

    /** {@code verification.resolve-signers}. */
    RESOLVE_SIGNERS("resolve-signers"),
    /** {@code verification.import-to-keyring}. */
    IMPORT_TO_KEYRING("import-to-keyring"),
    /** {@code verification.keyservers}, comma-separated. */
    KEYSERVERS("keyservers");

    private final String key;

    FetchSetting(String key) {
        this.key = key;
    }

    @Override
    public String key() {
        return key;
    }
}
