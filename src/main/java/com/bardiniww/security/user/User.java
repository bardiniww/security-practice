package com.bardiniww.security.user;


import lombok.*;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;


@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity(name = "User")
@Table(name = "_user")
public class User {
    @Id
    @GeneratedValue //sequence will be chosen by default, because of postgresql
    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String password;
}
