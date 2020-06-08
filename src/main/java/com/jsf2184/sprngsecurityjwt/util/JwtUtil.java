package com.jsf2184.sprngsecurityjwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class JwtUtil {

    private static final String SECRET_KEY = "secret";
    public static final int MS_PER_HOUR = 1000 * 60 * 60;


    public static String extractSubject(final String token) {
        final String result = extractClaim(token, claims -> claims.getSubject());
        return result;
    }

    public static Date extractExpiration(final String token) {
        final Date result = extractClaim(token, claims -> claims.getExpiration());
        return result;
    }

    public static <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        final T result = claimsResolver.apply(claims);
        return result;
    }

    public static Object extractFromMap(String key, String token) {
        final Object result = extractClaim(token, claims -> claims.get(key));
        return result;
    }

    public static Claims extractAllClaims(String token) {
        final Claims claims = Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
        return claims;
    }

    public static boolean isTokenExpired(String token, Date now) {
        final boolean result = extractExpiration(token).before(now);
        return result;
    }

    public static UsernamePasswordAuthenticationToken extractAuthenticationToken(String token) {
        final Claims claims = extractAllClaims(token);
        final String subject = claims.getSubject();
        final Object authoritiesObj = claims.get("authorities");
        List<GrantedAuthority> authorities = null;
        if (authoritiesObj != null && authoritiesObj instanceof Map) {
            Map<String, String> authorityMap = (Map<String, String>) authoritiesObj;
            authorities = authorityMap.keySet()
                                      .stream()
                                      .map(SimpleGrantedAuthority::new)
                                      .collect(Collectors.toList());
        }
        UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(subject, null, authorities);
        return result;
    }

    public static String generateToken(UserDetails userDetails) {
        final Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();

        Map<String, Object> claims = new HashMap<>();
        if (!CollectionUtils.isEmpty(authorities)) {
            final Map<String, String> authorityMap = toAuthorityMap(authorities);
            claims.put("authorities", authorityMap);
        }
        final String result = createToken(claims, userDetails.getUsername());
        return result;
    }


    public static Map<String, String> toAuthorityMap(Collection<? extends GrantedAuthority> authorities) {
        final Map<String, String> result =
                authorities.stream()
                           .map(GrantedAuthority::getAuthority)
                           .collect(Collectors.toMap(s -> s, s -> s));
        return result;
    }

    public static String createToken(Map<String, Object> claims, String subject) {
        Date now = new Date(System.currentTimeMillis());
        int expireMillis = 10 * MS_PER_HOUR;
        final String result = createToken(claims, subject, now, expireMillis);
        return result;
    }

    public static String createToken(Map<String, Object> claims,
                                     String subject,
                                     Date now,
                                     int expireMs) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.MILLISECOND, expireMs);
        final Date expire = calendar.getTime();

        final String result = Jwts
                .builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expire)
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();

        return result;
    }


}
