package com.cos.jwtex01.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.dto.LoginRequestDto;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 스프링시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// /login 요청해서 username, password전송하면(post)
// UsernamePasswordAuthenticationFilter 동작
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;

	// Authentication 객체 만들어서 리턴 => 의존 : AuthenticationManager
	// 인증 요청시에 실행되는 함수 => /login
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {

		System.out.println("JwtAuthenticationFilter : 진입");

		// 1. request에 있는 username과 password를 파싱해서 자바 Object로 받기
		// 2. authenticationManager로 로그인을 시도하면 PrincipalDetailis가 호출
		// loadUserByUsername() 함수 실행
		// 3. PrincipalDetailis를 세션에 담고(권한관리를 위해서)
		// 4. JWT토큰을 만들어서 응답
		ObjectMapper om = new ObjectMapper();
		LoginRequestDto loginRequestDto = null;
		try {
			loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("JwtAuthenticationFilter : " + loginRequestDto);

		// 유저네임패스워드 토큰 생성
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
				loginRequestDto.getUsername(), loginRequestDto.getPassword());

		System.out.println("JwtAuthenticationFilter : 토큰생성완료");

		// authenticate() 함수가 호출 되면 인증 프로바이더가 유저 디테일 서비스의
		// loadUserByUsername(토큰의 첫번째 파라메터) 를 호출하고
		// UserDetails를 리턴받아서 토큰의 두번째 파라메터(credential)과
		// UserDetails(DB값)의 getPassword()함수로 비교해서 동일하면
		// Authentication 객체를 만들어서 필터체인으로 리턴해준다.

		// Tip: 인증 프로바이더의 디폴트 서비스는 UserDetailsService 타입
		// Tip: 인증 프로바이더의 디폴트 암호화 방식은 BCryptPasswordEncoder
		// 결론은 인증 프로바이더에게 알려줄 필요가 없음.

		// PrincipalDetailsSerivce의 loadUserByUsername() 함수가 실행됨 정상이면 authentication리턴
		// DB에 있는 username password가 일치
		Authentication authentication = // authentication에 로그인 정보가 담김
				authenticationManager.authenticate(authenticationToken);
		// authentication객체가 session영역에 저장 => 로그인이 됨
		PrincipalDetails principalDetailis = (PrincipalDetails) authentication.getPrincipal(); // 다운캐스팅
		System.out.println("Authentication : " + principalDetailis.getUser().getUsername()); // 잘나오면 로그인이 잘되었다는 뜻
		// authentication 객체가 session영역에 저장하고 그방법이 return
		// 리턴의 이유는 권한관리를 security가 대신해서 
		// JWT토큰을 사용하면서 세션을 만들 이유가 없음. 권한처리때문에 session 넣어줌
		
		return authentication;
	}

	// JWT Token 생성해서 response에 담아주기
	// attemptAuthentication실행후 인증이 정상적이면 successfulAuthentication함수 실행
	// JWT토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {

		PrincipalDetails principalDetailis = (PrincipalDetails) authResult.getPrincipal();

		String jwtToken = JWT.create().withSubject(principalDetailis.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))// 만료시간 설정
				.withClaim("id", principalDetailis.getUser().getId())
				.withClaim("username", principalDetailis.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET));

		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
	}

}
