package de.sresec.springsecurity.security;

import static de.sresec.springsecurity.security.Permission.COURSE_WRITE;
import static de.sresec.springsecurity.security.Role.ADMIN;
import static de.sresec.springsecurity.security.Role.STUDENT;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

  private final PasswordEncoder passwordEncoder;

  @Autowired
  public WebSecurityConfiguration(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .csrf().disable()
        .authorizeRequests()
        .antMatchers("/","/error", "/css/**", "/img/**").permitAll()
        .antMatchers("/api/student/**").hasRole(STUDENT.name())
        . anyRequest()
        .authenticated()
        .and()
        .formLogin()
        .loginPage("/login").permitAll();
  }

  @Override
  @Bean
  protected UserDetailsService userDetailsService() {
    UserDetails joseph;
    joseph = User.
        builder()
        .username("Joseph")
        .password(passwordEncoder.encode("password"))
        .authorities(STUDENT.getGrantedAuthorities())
        .build();

    UserDetails Dons = User.
        builder()
        .username("Dons")
        .password(passwordEncoder.encode("password123"))
        .authorities(ADMIN.getGrantedAuthorities())
        .build();

    return new InMemoryUserDetailsManager(
        joseph,Dons
    );
  }
}
