package de.sresec.springsecurity.controllers;

import de.sresec.springsecurity.student.Student;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("management/api/students")
public class StudentManagementController {

  private final static List<Student> STUDENTS = List.of(
      new Student(1L,"Joe Fess"),
      new Student(2L,"Geo Famo"),
      new Student(3L,"Jas Frem"),
      new Student(4L,"Dan Fess")
  );

//    hasRole('ROLE_') hasAnyRole('ROLE_') hasAuthority('permission') hasAnyAuthority('permission')

  @GetMapping
  @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
  public List<Student> getAllStudents() {
    System.out.println("getAllStudents");
    return STUDENTS;
  }

  @PostMapping
  public void registerNewStudent(@RequestBody Student student) {
//    STUDENTS.add(new Student((long) STUDENTS.size(),student.getName()));
    System.out.println("registerNewStudent");
    System.out.println(student);
  }

  @DeleteMapping(path = "{studentId}")
  public void deleteStudent(@PathVariable("studentId") Integer studentId) {
    System.out.println("deleteStudent");
    System.out.println(studentId);
  }

  @PutMapping(path = "{studentId}")
  public void updateStudent(@PathVariable("studentId") Integer studentId,
      @RequestBody Student student) {
    System.out.println("updateStudent");
    System.out.printf("%s %s%n", studentId, student);
  }
}