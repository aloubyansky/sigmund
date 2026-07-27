package dev.cyberstamp.sigmund.core;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class KeyFetchCacheTest {

    @Test
    void shouldAttemptReturnsTrueByDefault() {
        var cache = new KeyFetchCache();
        assertTrue(cache.shouldAttempt("hkps://keys.example.com", "ABCD1234"));
    }

    @Test
    void connectionFailureTripsCircuitForThatServer() {
        var cache = new KeyFetchCache();
        cache.recordConnectionFailure("hkps://down.example.com");

        assertFalse(cache.shouldAttempt("hkps://down.example.com", "ABCD1234"));
        assertTrue(cache.shouldAttempt("hkps://up.example.com", "ABCD1234"));
    }

    @Test
    void keyNotFoundBlocksKeyAcrossServers() {
        var cache = new KeyFetchCache();
        cache.recordKeyNotFound("DEADBEEF");

        assertFalse(cache.shouldAttempt("hkps://server1.example.com", "DEADBEEF"));
        assertFalse(cache.shouldAttempt("hkps://server2.example.com", "DEADBEEF"));
        assertTrue(cache.shouldAttempt("hkps://server1.example.com", "OTHER123"));
    }

    @Test
    void successDoesNotAffectOtherKeys() {
        var cache = new KeyFetchCache();
        cache.recordSuccess("hkps://keys.example.com", "ABCD1234");

        assertTrue(cache.shouldAttempt("hkps://keys.example.com", "ABCD1234"));
        assertTrue(cache.shouldAttempt("hkps://keys.example.com", "OTHER123"));
    }

    @Test
    void circuitBreakerAndNegativeCacheCombine() {
        var cache = new KeyFetchCache();
        cache.recordConnectionFailure("hkps://down.example.com");
        cache.recordKeyNotFound("DEADBEEF");

        assertFalse(cache.shouldAttempt("hkps://down.example.com", "DEADBEEF"));
        assertFalse(cache.shouldAttempt("hkps://down.example.com", "OTHER123"));
        assertFalse(cache.shouldAttempt("hkps://up.example.com", "DEADBEEF"));
        assertTrue(cache.shouldAttempt("hkps://up.example.com", "OTHER123"));
    }
}
