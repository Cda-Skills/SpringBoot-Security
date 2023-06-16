package org.tuto.springSecurity6.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;



@Configuration
public class SecurityConfig {
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		
		httpSecurity.authorizeHttpRequests((connex) -> connex
						.requestMatchers("/inscription").hasRole("USER")
						.requestMatchers("/listUser").hasRole("ADMIN")
						.requestMatchers("/").permitAll()
						.anyRequest()
						.authenticated()
						)
		
						.httpBasic();

		return httpSecurity.build(); 
	}

	@Bean
	public InMemoryUserDetailsManager userDetailService() {
		
		UserDetails user = User.builder()
				.username("user")
				.password(passwordEncoder().encode("Password"))
				.roles("USER")
				.build();
		
		UserDetails admin = User.builder()
				.username("Admin")
				.password(passwordEncoder().encode("StrongPass"))
				.roles("ADMIN")
				.build();
		
		return new InMemoryUserDetailsManager(user, admin);
	}
	
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
