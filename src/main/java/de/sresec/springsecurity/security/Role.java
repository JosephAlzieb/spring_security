package de.sresec.springsecurity.security;

import static de.sresec.springsecurity.security.Permission.COURSE_READ;
import static de.sresec.springsecurity.security.Permission.COURSE_WRITE;

import com.google.common.collect.Sets;
import java.util.Set;

public enum Role {
  STUDENT(Sets.newHashSet(COURSE_READ)),
  ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE));

  private final Set<Permission> permissions;

  Role(Set<Permission> permissions) {
    this.permissions = permissions;
  }

  public Set<Permission> getPermissions() {
    return permissions;
  }
}
