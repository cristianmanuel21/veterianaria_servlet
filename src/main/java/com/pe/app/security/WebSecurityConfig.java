package com.pe.app.security;

import com.pe.app.security.jwt.AuthEntryPointJwt;
import com.pe.app.security.jwt.AuthTokenFilter;
import com.pe.app.security.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
  @Autowired
  UserDetailsServiceImpl userDetailsService;

  @Autowired
  private AuthEntryPointJwt unauthorizedHandler;

  @Bean
  AuthTokenFilter authenticationJwtTokenFilter() {
    return new AuthTokenFilter();
  }

  private static final String[] AUTH_WHITELIST = {
		// -- Swagger UI v2
          "/v2/api-docs",
          "/swagger-resources",
          "/swagger-resources/**",
          "/configuration/ui",
          "/configuration/security",
          "/swagger-ui.html",
          "/webjars/**",
          // -- Swagger UI v3 (OpenAPI)
          "/v3/api-docs/**",
          "/swagger-ui/**"
  };

  @Bean
  DaoAuthenticationProvider authenticationProvider() {
      DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
      authProvider.setUserDetailsService(userDetailsService);
      authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
  }


  @Bean
  AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
    return authConfig.getAuthenticationManager();
  }


  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }


  @Bean
  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.cors().and().csrf().disable()
        .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
        .authorizeRequests()
        .antMatchers("/api/auth/**").permitAll()
        .antMatchers(AUTH_WHITELIST).permitAll()
        .antMatchers(HttpMethod.GET,"/chip","/chip/**").hasAnyRole("USER","ADMIN","MODERATOR")
        .antMatchers("/chip/**").hasAnyRole("ADMIN","MODERATOR")//incluye el post, put y delete
        .antMatchers(HttpMethod.GET,"/animal","/animal/**").hasAnyRole("USER","ADMIN","MODERATOR")
        .antMatchers("/animal/**").hasAnyRole("ADMIN","MODERATOR")
        .antMatchers("/duenoveterinaria/**").hasAnyRole("ADMIN","MODERATOR")
        .antMatchers(HttpMethod.GET,"/mascota","/mascota/**").hasAnyRole("USER","ADMIN","MODERATOR")
        .antMatchers("/mascota/**").hasAnyRole("ADMIN","MODERATOR")
        .antMatchers(HttpMethod.GET,"/veterinaria","/veterinaria/**").hasAnyRole("USER","ADMIN","MODERATOR")
        .antMatchers("/veterinaria/**").hasAnyRole("ADMIN","MODERATOR")
        .anyRequest().authenticated();
    
    http.authenticationProvider(authenticationProvider());
    http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    return http.build();
    
  }
}
