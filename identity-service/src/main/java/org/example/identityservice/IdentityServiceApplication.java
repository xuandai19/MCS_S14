package org.example.identityservice;

import org.example.identityservice.models.constants.RoleName;
import org.example.identityservice.models.entities.Role;
import org.example.identityservice.models.repositories.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class IdentityServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(IdentityServiceApplication.class, args);
    }


    @Bean
    public CommandLineRunner  commandLineRunner(RoleRepository roleRepository){
        return args -> {
            if (roleRepository.count() == 0){
                Role role1 = new Role(null, RoleName.ROLE_ADMIN);
                Role role2= new Role(null, RoleName.ROLE_USER);
                roleRepository.save(role1);
                roleRepository.save(role2);
            }
        };
    }
}
