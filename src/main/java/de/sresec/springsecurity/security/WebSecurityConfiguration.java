package de.sresec.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

  private PasswordEncoder passwordEncoder;

  @Autowired
  public WebSecurityConfiguration(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
//        .antMatchers("/","/error", "/css/**", "/img/**").permitAll()
        .antMatchers("/student/**").hasRole(Role.ADMIN.name())
        .anyRequest()
        .authenticated()
        .and()
        .httpBasic();
  }

  @Override
  @Bean
  protected UserDetailsService userDetailsService() {
    UserDetails joseph = User.
        builder()
        .username("Joseph")
        .password(passwordEncoder.encode("password"))
        .roles(Role.STUDENT.name()) //  ROLLE_STUDENT
        .build();

    UserDetails Dons = User.
        builder()
        .username("Dons")
        .password(passwordEncoder.encode("password"))
        .roles(Role.ADMIN.name()) //  ROLLE_STUDENT
        .build();

    return new InMemoryUserDetailsManager(
        joseph,Dons
    );
  }
}
