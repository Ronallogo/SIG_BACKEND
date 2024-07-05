package com.security.securitySpring.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "DyPuuQRwVDeYazS2LtIqBrEAgdwUpIJ4uvnCcwul59k+AyRfZrsfxHjJio4yg1Rw9KIrNR+H6e2Qp6Jp8DGGA9M+JvQ3VacPJcyxGDKg91NmNo8EIoTyRNr3UvhvHn0GnxunNJWvB4HiNFV7o1/GnJdMmEV5ZBX4UTlDAlZOF4KIQ7BpSgw08keA1Jd+aC8l+3hVNxP9qQ7KpqUJWYFeMUFIFV5AvANqrhWjcJdzhkZUNczoFI4kzl8eN/+3LdbzrKyoa/V/M1o/G7A8MTwkF9Br8tH/y+bnaAd0dlGyFNph2ZjWy2kQpoN+HwSOK5ShQXBW+cEEeioHtxxKXagVAL9vfQTLgEad0VpsyEN/LGk";

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(getSigninKey())
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            // Log the exception and handle it appropriately
            throw new RuntimeException("Failed to extract claims from token", e);
        }
    }

    private Key getSigninKey() {
        byte[] decodedKey = Base64.getDecoder().decode(SECRET_KEY);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "HmacSHA256");
    }

    public String generateTokenJwt(UserDetails userDetails) {
        return generateToken(userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUserName(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 10 hours
                .signWith(SignatureAlgorithm.HS256, getSigninKey())
                .compact();
    }
}
