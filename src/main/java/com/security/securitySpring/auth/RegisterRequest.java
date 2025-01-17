package com.security.securitySpring.auth;


import com.security.securitySpring.Entity.Roles;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.management.relation.Role;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {

    private String firstname ;
    private String lastname ;
    private String email  ;
    private String password ;
    private Roles role;


}
