package com.oauth2.convert;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CustomRoleConvert implements Converter<Jwt, Collection<GrantedAuthority>> {

    private String PREFIX = "ROLE_";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        String scope = jwt.getClaimAsString("scope");
        Map<String, Object> realm_access = jwt.getClaimAsMap("realm_access");

        if (scope == null || realm_access == null) {
            return Collections.EMPTY_LIST;
        }

        List<GrantedAuthority> authorities1 = Arrays.stream(scope.split(" "))
                .map(roleName -> PREFIX + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        List<GrantedAuthority> authorities2 = ((List<String>) realm_access.get("roles"))
                .stream()
                .map(roleName -> PREFIX + roleName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        authorities1.addAll(authorities2);
        return authorities1;
    }
}
