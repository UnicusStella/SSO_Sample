package com.dreamsecurity.sso.server.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CORSFilter implements Filter
{
	public void init(FilterConfig filterConfig) throws ServletException
	{
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
	{
		HttpServletRequest httprequest = (HttpServletRequest) request;
		HttpServletResponse httpresponse = (HttpServletResponse) response;

		httpresponse.setHeader("Access-Control-Allow-Origin", httprequest.getHeader("Origin"));
		httpresponse.setHeader("Access-Control-Allow-Credentials", "true");
		httpresponse.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
		httpresponse.setHeader("Access-Control-Max-Age", "86400");
		httpresponse.setHeader("Access-Control-Allow-Headers", "*");

		chain.doFilter(request, response);
	}

	public void destroy()
	{
	}
}