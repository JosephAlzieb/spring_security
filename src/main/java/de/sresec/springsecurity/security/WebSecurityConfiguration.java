package de.sresec.springsecurity.security;

import static de.sresec.springsecurity.security.Permission.COURSE_WRITE;
import static de.sresec.springsecurity.security.Role.ADMIN;
import static de.sresec.springsecurity.security.Role.STUDENT;

import java.util.concurrent.TimeUnit;
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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

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
        .loginPage("/login").permitAll()
        .defaultSuccessUrl("/courses",true)
        .and()
        .rememberMe()
            .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
            .key("verysecured")
        .and()
        .logout()
        .logoutUrl("/logout")
        // DIE UNTERE ZEILE IST NUR DA WEIL CSRF-TOKEN DISABLED IST, BEI ENABLE SOLLTE SIE GELÖSCHT WERDEN,
        // DENN WIR MÜSSEN DANN POST-METHODE VERWENDEN, UND NICHT GET..
        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "POST"))
        .clearAuthentication(true)
        .invalidateHttpSession(true)
        .deleteCookies("JSESSIONID","remember-me")
        .logoutSuccessUrl("/login");
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
