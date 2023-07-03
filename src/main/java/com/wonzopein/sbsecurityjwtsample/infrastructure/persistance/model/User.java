package com.wonzopein.sbsecurityjwtsample.infrastructure.persistance.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.wonzopein.sbsecurityjwtsample.infrastructure.consts.auth.Role;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "TB_USER")
@Getter
@Setter
public class User extends BaseEntity {

    @Id
    private String username;

    @JsonIgnore
    @NotBlank
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    private String name;

}
