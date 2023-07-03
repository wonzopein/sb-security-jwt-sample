package com.wonzopein.sbsecurityjwtsample.infrastructure.consts.auth;

public enum Role {
    ADMIN,
    USER,
    GUEST;

    public String authority() {
        return "ROLE_" + this.name();
    }
}
