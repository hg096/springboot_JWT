package com.cos.jwtex01.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter1 implements Filter {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;

		// 토큰 cos 이걸 만들어줘야 함. id,pw정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답
		// 요청마다 header에 Authorization에 value값으로 토큰을 가지고옴
		// 크때 토큰이 넘어오면 이토큰이 내가만든 토큰인지 검증 (RSA,HS256)
		if (req.getMethod().equals("POST")) {
			System.out.println("POST 요청됨");
			String headerAuth = req.getHeader("Authorization");
			System.out.println(headerAuth);
			System.out.println("필터 1");

			if (headerAuth.equals("cos")) {
				chain.doFilter(req, res);
			} else {
				PrintWriter out = res.getWriter();
				out.println("인증안됨");
			}
		}

	}

}
