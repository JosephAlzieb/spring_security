package de.sresec.springsecurity.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtTokenVerifier extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    String authorizationHeader = request.getHeader("Authorization");

    if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);
      return;
    }

    String token = authorizationHeader.replace("Bearer ", "");
    String key = "securesecuresecuresecuresecuresecuresecuresecuresecuresecuresecuresecuresecuresecuresecuresecuresecuresecuresecure";

    try {
      Jws<Claims> claimsJws = Jwts.parserBuilder()
          .setSigningKey(Keys.hmacShaKeyFor(key.getBytes()))
          .build()
          .parseClaimsJws(token);

      Claims body = claimsJws.getBody();
      String username = body.getSubject();

      var authorization = (List<Map<String , String>>)body.get("Authorization");

      Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorization.stream()
          .map(e -> new SimpleGrantedAuthority(e.get("authority")))
          .collect(Collectors.toSet());
      Authentication authentication = new UsernamePasswordAuthenticationToken(
          username,
          null,
          simpleGrantedAuthorities
      );
      SecurityContextHolder.getContext().setAuthentication(authentication);
    }catch (JwtException e){
      throw new IllegalStateException("Token can not be trust");
    }

    filterChain.doFilter(request,response);
  }
}
