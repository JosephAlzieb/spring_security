package de.sresec.springsecurity.security;

import static de.sresec.springsecurity.security.Permission.COURSE_READ;
import static de.sresec.springsecurity.security.Permission.COURSE_WRITE;
import static de.sresec.springsecurity.security.Permission.STUDENT_READ;
import static de.sresec.springsecurity.security.Permission.STUDENT_WRITE;

import com.google.common.collect.Sets;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public enum Role {
  STUDENT(Sets.newHashSet()),
  ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE,STUDENT_READ,STUDENT_WRITE));

  private final Set<Permission> permissions;

  Role(Set<Permission> permissions) {
    this.permissions = permissions;
  }

  private Set<Permission> getPermissions() {
    return permissions;
  }

  public Set<SimpleGrantedAuthority> getGrantedAuthorities(){
    Set<SimpleGrantedAuthority> grantedAuthorities = getPermissions().stream()
        .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
        .collect(Collectors.toSet());

    grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));

    return grantedAuthorities;
  }
}
