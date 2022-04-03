package de.sresec.springsecurity.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class TemplatesController {

  @GetMapping("login")
  public String getLoginPage(){
    return "login";
  }

  @GetMapping("courses")
  public String getCoursesPage(){
    return "courses";
  }
}
