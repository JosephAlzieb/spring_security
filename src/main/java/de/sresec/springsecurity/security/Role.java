package de.sresec.springsecurity.security;

import static de.sresec.springsecurity.security.Permission.COURSE_READ;
import static de.sresec.springsecurity.security.Permission.COURSE_WRITE;
import static de.sresec.springsecurity.security.Permission.STUDENT_READ;
import static de.sresec.springsecurity.security.Permission.STUDENT_WRITE;

import com.google.common.collect.Sets;
import java.util.Set;

public enum Role {
  STUDENT(Sets.newHashSet()),
  ADMIN(Sets.newHashSet(COURSE_READ, COURSE_WRITE,STUDENT_READ,STUDENT_WRITE));

  private final Set<Permission> permissions;

  Role(Set<Permission> permissions) {
    this.permissions = permissions;
  }

  public Set<Permission> getPermissions() {
    return permissions;
  }
}
