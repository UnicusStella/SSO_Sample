package com.dreamsecurity.sso.server.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.util.Util;

public class SSLFilter implements Filter
{
	public void init(FilterConfig filterConfig) throws ServletException
	{
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
	{
		HttpServletRequest httprequest = (HttpServletRequest) request;

		String url = httprequest.getServletPath();

		int index = url.indexOf(".jsp");
		if (index == -1) {
			chain.doFilter(request, response);
			return;
		}

		if (SSOConfig.getInstance().getSSLUse()) {
			if (request.isSecure()) {
				chain.doFilter(request, response);
			}
			else {
				String connIp = httprequest.getRemoteAddr();
				String connProtocol = httprequest.getProtocol();
				Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
						SSOConfig.getInstance().getServerName(), "AK", "1", connIp + ", " + connProtocol + ", " + url);

				response.setContentType("text/html; charset=utf-8");

				PrintWriter out = response.getWriter();
				out.println("<HTML>");
				out.println("<HEAD><TITLE>Magic SSO 서버 접속 실패</TITLE></HEAD>");
				out.println("<BODY>");
				out.println("<H3></br>&nbsp;Use HTTPS (TLS v1.2 or higher, SSH v2 or higher).</H3>");
				out.println("</BODY>");
				out.println("</HTML>");
				out.flush();
				out.close();
			}
		}
		else {
			chain.doFilter(request, response);
		}
	}

	public void destroy()
	{
	}
}