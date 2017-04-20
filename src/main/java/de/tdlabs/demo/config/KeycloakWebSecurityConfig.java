package de.tdlabs.demo.config;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.representations.AccessToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import static org.springframework.context.annotation.ScopedProxyMode.TARGET_CLASS;
import static org.springframework.web.context.WebApplicationContext.SCOPE_REQUEST;

@Configuration
@EnableWebSecurity
@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
class KeycloakWebSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

  /**
   * Expose the current {@link AccessToken} on RequestScope.
   *
   * Can be autowired as a Request Scoped Proxy.
   *
   * @return
   */
  @Bean
  @Scope(scopeName = SCOPE_REQUEST, proxyMode = TARGET_CLASS)
  AccessToken getAccessToken() {

    KeycloakSecurityContext context = (KeycloakSecurityContext) RequestContextHolder //
      .currentRequestAttributes() //
      .getAttribute(KeycloakSecurityContext.class.getName(), RequestAttributes.SCOPE_REQUEST);
    return context.getToken();
  }

  /**
   * Registers the KeycloakAuthenticationProvider with the authentication
   * manager.
   */
  @Autowired
  public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {

    KeycloakAuthenticationProvider authProvider = keycloakAuthenticationProvider();
    auth.authenticationProvider(authProvider);
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    web.ignoring() //
      .antMatchers("/favicon.ico")
      .antMatchers(HttpMethod.OPTIONS, "/**");
  }

  /**
   * Defines the session authentication strategy.
   */
  @Bean
  @Override
  protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
    return new RegisterSessionAuthenticationStrategy(buildSessionRegistry());
  }

  @Bean
  protected SessionRegistry buildSessionRegistry() {
    return new SessionRegistryImpl();
  }


  @Override
  protected void configure(HttpSecurity http) throws Exception {
    super.configure(http);

    http
      .logout()
      .logoutRequestMatcher(new AntPathRequestMatcher("/sso/logout"))
      .and()
      .authorizeRequests() //
      .antMatchers("/api/**").authenticated() //
      .antMatchers("/admin/system/**").hasRole("ACTUATOR") // Role ROLE_ACTUATOR in Keycloak
      .antMatchers("/admin/**").hasRole("ADMIN")  // Role ROLE_ADMIN in Keycloak
      .anyRequest().permitAll();
  }
}