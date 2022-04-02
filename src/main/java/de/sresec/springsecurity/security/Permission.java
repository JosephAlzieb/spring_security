package de.sresec.springsecurity.security;

public enum Permission {
  COURSE_READ("read"),
  COURSE_WRITE("write");

  private final String permission;

  Permission(String permission) {
    this.permission = permission;
  }

  public String getPermission(){
    return permission;
  }
}
