package com.wonzopein.sbsecurityjwtsample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class SbSecurityJwtSampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(SbSecurityJwtSampleApplication.class, args);
    }

}
