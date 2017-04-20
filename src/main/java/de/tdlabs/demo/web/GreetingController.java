package de.tdlabs.demo.web;

import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
class GreetingController {

  @GetMapping("/api/greet")
  Object greet(@AuthenticationPrincipal KeycloakAuthenticationToken authenticationToken) {

    Map<String, Object> data = new LinkedHashMap<>();

    data.put("username", authenticationToken.getName());
    data.put("roles", AuthorityUtils.authorityListToSet(authenticationToken.getAuthorities()));
    data.put("greeting", "Hello " + authenticationToken.getName() + " " + LocalDateTime.now());

    return data;
  }
}
