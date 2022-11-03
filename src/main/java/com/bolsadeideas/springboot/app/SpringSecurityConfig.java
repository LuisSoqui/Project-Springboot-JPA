package com.bolsadeideas.springboot.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.bolsadeideas.springboot.app.auth.handler.LoginSuccessHandler;
import com.bolsadeideas.springboot.app.models.service.JpaUserDetailsService;

@EnableGlobalMethodSecurity(securedEnabled = true)
@Configuration
public class SpringSecurityConfig {
		
	final static String USER = "USER";
	final static String ADMIN = "ADMIN";
	
	@Autowired
	private LoginSuccessHandler successHanlder;
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	@Autowired
	private JpaUserDetailsService userDetailsService;
	
	@Bean
	public UserDetailsService userDetailsService(AuthenticationManagerBuilder build) throws Exception {

		build.userDetailsService(userDetailsService)
		.passwordEncoder(passwordEncoder);
	

		return build.getDefaultUserDetailsService();

	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		http.authorizeRequests().antMatchers("/", "/css/**", "/js/**", "/images/**", "/listar")
		.permitAll()
		//.antMatchers("/ver/**").hasAnyRole(USER)
		//.antMatchers("/uploads/**").hasAnyRole(USER)
		//.antMatchers("/form/**").hasAnyRole(ADMIN)
		//.antMatchers("/eliminar/**").hasAnyRole(ADMIN)
		//.antMatchers("/factura/**").hasAnyRole(ADMIN)
		.anyRequest()
		.authenticated()
		.and()
		.formLogin()
		.successHandler(successHanlder)
		.loginPage("/login")
		.permitAll()
		.and()
		.logout()
		.permitAll()
		.and()
		.exceptionHandling().accessDeniedPage("/error_403");

		return http.build();
	}

}
