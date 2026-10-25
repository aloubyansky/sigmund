package dev.cyberstamp.sigmund.plugin;

import dev.cyberstamp.sigmund.core.IdentityCredential;
import dev.cyberstamp.sigmund.core.KeyCredential;
import java.io.IOException;
import java.util.List;

/**
 * Asks directories which addresses they have verified for a key, as
 * {@code Sigmund.directoryIdentities} does; a seam so that an update can be tested without the
 * network.
 */
@FunctionalInterface
interface DirectoryLookup {

    /**
     * Returns the identities the directories among the issuers vouch for a key.
     *
     * @param key the key
     * @param issuers the issuers to ask; those that are not directories are skipped
     * @return each verified address as an email identity from its directory
     * @throws IOException if a directory cannot be reached
     */
    List<IdentityCredential> identities(KeyCredential key, List<String> issuers) throws IOException;
}
