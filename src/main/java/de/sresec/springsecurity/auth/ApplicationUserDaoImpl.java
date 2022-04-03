package de.sresec.springsecurity.auth;

import static de.sresec.springsecurity.security.Role.ADMIN;
import static de.sresec.springsecurity.security.Role.STUDENT;

import com.google.common.collect.Lists;
import java.util.List;
import java.util.Optional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

@Repository("fake")
public class ApplicationUserDaoImpl implements ApplicationUserDao{

  private final PasswordEncoder passwordEncoder;

  public ApplicationUserDaoImpl(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
    return getApplicationUsers()
        .stream()
        .filter(appUser -> appUser.getUsername().equals(username))
        .findFirst();
  }

  private List<ApplicationUser> getApplicationUsers() {
    return Lists.newArrayList(
        new ApplicationUser(
            "Joseph",
            passwordEncoder.encode("password"),
            STUDENT.getGrantedAuthorities(),
            true,
            true,
            true,
            true
        ),
        new ApplicationUser(
            "Dons",
            passwordEncoder.encode("password"),
            ADMIN.getGrantedAuthorities(),
            true,
            true,
            true,
            true
        )
    );
  }
}
