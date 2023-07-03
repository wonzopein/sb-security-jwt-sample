package com.wonzopein.sbsecurityjwtsample.infrastructure.rest.model.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;
import org.hibernate.validator.constraints.Length;

public class AuthenticationDto {

    /**
     * 가입
     */
    public static class Signup {

        @Length(min = 5)
        @NotBlank
        private String username;

        @Length(min = 5)
        @NotBlank
        private String password;

        @Email
        @NotBlank
        private String email;
    }

    /**
     * 사용자 인증 요청
     */
    @Data
    public static class SigninRequest {
        @Length(min = 5)
        @NotBlank
        private String username;
        @Length(min = 5)
        @NotBlank
        private String password;
    }

    /**
     * 사용자 인증 결과
     */
    @Builder
    @Data
    @NoArgsConstructor
    public static class SigninResponse {
        private String accessToken;
        private String username;

        public SigninResponse(String accessToken, String username) {
            this.accessToken = accessToken;
            this.username = username;
        }
    }

}
