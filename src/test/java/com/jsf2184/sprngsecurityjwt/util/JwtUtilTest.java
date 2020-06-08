package com.jsf2184.sprngsecurityjwt.util;

import com.jsf2184.sprngsecurityjwt.SecurityConfiguration;
import com.jsf2184.sprngsecurityjwt.Simple;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;
import java.util.stream.Collectors;

class JwtUtilTest {

    private static final String MAP_KEY = "key";

    @Test
    public void testCommonScenario() {
        final String mapValue = "value";
        final String token = createToken("subject", mapValue);
        Assert.assertEquals("subject", JwtUtil.extractSubject(token));
        Assert.assertEquals(mapValue, JwtUtil.extractFromMap(MAP_KEY, token));

    }

    @Test
    public void testExpire() throws InterruptedException {
        final String mapValue = "value";
        final long millis = System.currentTimeMillis();
        final Date now = new Date(millis);
        final String token = createToken("subject",
                                         mapValue,
                                         now,
                                         1000);

        Thread.sleep(2000);

        boolean caught = false;
        try {
            final String extractSubject = JwtUtil.extractSubject(token);
        } catch (ExpiredJwtException e) {
            caught = true;
        }
        Assert.assertTrue(caught);

    }


    @Test
    public void testObjectInMap() {
        final String simpleAttributeValue = "value";
        Simple mapValue = new Simple(simpleAttributeValue);
        final String token = createToken("subject", mapValue);
        Assert.assertEquals("subject", JwtUtil.extractSubject(token));

        // It does some funny stuff here, that I may want explore later. For now, I just have
        // asserts that verify how it works not that I totally understand it.
        //
        final Object extractedValue = JwtUtil.extractFromMap(MAP_KEY, token);
        Assert.assertTrue(extractedValue instanceof Map);
        Map extractedMap = (Map) extractedValue;
        Assert.assertEquals(1, extractedMap.size());
        Assert.assertEquals(simpleAttributeValue, extractedMap.get("data"));
    }

    @Test
    public void testTokenRoundTrip() {
        String userName = "JOEY";
        final UserDetails userDetails = SecurityConfiguration.FAKE_USER_DETAILS_SERVICE.loadUserByUsername(userName);
        final String jwtToken = JwtUtil.generateToken(userDetails);
        final UsernamePasswordAuthenticationToken authenticationToken = JwtUtil.extractAuthenticationToken(jwtToken);
        Assert.assertEquals(userName, authenticationToken.getPrincipal());
        final Set<String> expectedAuthorities = toAuthoritySet(userDetails.getAuthorities());
        final Set<String> actualAuthorities = toAuthoritySet(authenticationToken.getAuthorities());
        Assert.assertEquals(expectedAuthorities, actualAuthorities);
    }

    @Test
    public void testTokenRoundTrip2() {
        String userName = "JOEY";
        final UserDetails userDetails = SecurityConfiguration.FAKE_USER_DETAILS_SERVICE.loadUserByUsername(userName);
        final String jwtToken = JwtUtil.generateToken(userDetails);
        final UsernamePasswordAuthenticationToken authenticationToken = JwtUtil.extractAuthenticationToken(jwtToken);
        Assert.assertEquals(userName, authenticationToken.getPrincipal());
        final Set<String> expectedAuthorities = toAuthoritySet(userDetails.getAuthorities());
        final Set<String> actualAuthorities = toAuthoritySet(authenticationToken.getAuthorities());
        Assert.assertEquals(expectedAuthorities, actualAuthorities);
    }


    Set<String> toAuthoritySet(Collection<? extends GrantedAuthority> authorities) {
        final Set<String> result = authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        return result;
    }

    @Test
    public void verifyMapTampering() {
        final String token1 = createToken("subject", "value1");
        final String token2 = createToken("subject", "value2");
        tamperAndVerifyException(token1, token2);
    }

    @Test
    public void verifyTimeTampering() throws InterruptedException {
        final String token1 = createToken("subject", "value1");
        Thread.sleep(2000);
        final String token2 = createToken("subject", "value2");
        tamperAndVerifyException(token1, token2);
    }


    public static void tamperAndVerifyException(final String token1, final String token2) {
        final String[] parts1 = token1.split("\\.");
        final String[] parts2 = token2.split("\\.");

        String tamperedToken = parts1[0] + "." + parts2[1] + "." + parts1[2];

        boolean caught = false;
        try {
            final String extractSubject = JwtUtil.extractSubject(tamperedToken);
        } catch (SignatureException e) {
            caught = true;
        }
        Assert.assertTrue(caught);

    }

    public static String createToken(String subject,
                                     Object mapValue) {
        Map<String, Object> map = new HashMap<>();
        map.put(MAP_KEY, mapValue);
        final String result = createToken(subject,
                                          mapValue,
                                          new Date(System.currentTimeMillis()),
                                          JwtUtil.MS_PER_HOUR * 10);

        return result;
    }


    public static String createToken(String subject,
                                     Object mapValue,
                                     Date now,
                                     int expireMs) {
        Map<String, Object> map = new HashMap<>();
        map.put(MAP_KEY, mapValue);
        final String result = JwtUtil.createToken(map, subject, now, expireMs);
        return result;
    }
}