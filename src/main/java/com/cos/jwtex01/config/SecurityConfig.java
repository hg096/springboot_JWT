package com.cos.jwtex01.config;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import com.cos.jwtex01.config.jwt.JwtAuthenticationFilter;
import com.cos.jwtex01.config.jwt.JwtAuthorizationFilter;
import com.cos.jwtex01.filter.MyFilter1;
import com.cos.jwtex01.repository.UserRepository;

@Configuration
@EnableWebSecurity // 시큐리티 활성화 -> 기본 스프링 필터체인에 등록
public class SecurityConfig extends WebSecurityConfigurerAdapter{	
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private CorsConfig corsConfig;
	
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				// .addFilterBefore(new MyFilter1(), SecurityContextPersistenceFilter.class) // 가장먼저 실행되는 필터
				// .addFilterAfter(new MyFilter1(), BasicAuthenticationFilter.class)
				.addFilter(corsConfig.corsFilter()) // 필터걸기 @CrossOrigin(인증x), 시큐리티 필터에 등록인증(O)
				.csrf().disable() // csrf 토큰 비활성화(테스트시 걸어두기)
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
				.formLogin().disable() // 폼 테그 로그인 x
				.httpBasic().disable() // https 방식으로 토큰을 사용하기위해서 필요
				
				.addFilter(new JwtAuthenticationFilter(authenticationManager())) //토큰관련 필터 등록
				.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))
				.authorizeRequests()
				.antMatchers("/api/v1/user/**") // 접근 URL
				.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // 접근 권한
				.antMatchers("/api/v1/manager/**")
					.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
				.antMatchers("/api/v1/admin/**")
					.access("hasRole('ROLE_ADMIN')")
				.anyRequest().permitAll();
	}
}






