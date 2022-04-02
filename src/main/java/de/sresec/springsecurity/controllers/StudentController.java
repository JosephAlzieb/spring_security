package de.sresec.springsecurity.controllers;

import de.sresec.springsecurity.student.Student;
import java.util.List;
import java.util.NoSuchElementException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/student")
public class StudentController {

  private final static List<Student> STUDENTS = List.of(
      new Student(1L,"Joe Fess"),
      new Student(2L,"Geo Famo"),
      new Student(3L,"Jas Frem"),
      new Student(4L,"Dan Fess")
  );

  @GetMapping("{studentid}")
  public Student getStudent(@PathVariable("studentid") Long id){
    return STUDENTS.stream()
        .filter(s -> s.getId().equals(id))
        .findFirst()
        .orElseThrow(()-> new NoSuchElementException("Es existiert keinen Student mit dem Id -- "+ id));
  }
}
