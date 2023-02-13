package com.dreamsecurity.sso.agent.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.dreamsecurity.sso.agent.config.SSOConfig;
import com.dreamsecurity.sso.agent.crypto.CryptoApi;
import com.dreamsecurity.sso.agent.crypto.CryptoApiFactory;
import com.dreamsecurity.sso.agent.util.Util;

public class SessionFilter implements Filter
{
	public void init(FilterConfig filterConfig) throws ServletException
	{
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
	{
		HttpServletRequest httprequest = (HttpServletRequest) request;
		HttpServletResponse httpresponse = (HttpServletResponse) response;
		HttpSession session = httprequest.getSession();

		String url = httprequest.getServletPath();
		int index = url.indexOf("Logout.jsp");
		if (index >= 0) {
			chain.doFilter(request, response);
			return;
		}

		String userId = (String) session.getAttribute("SSO_ID");
		if (userId == null || "".equals(userId)) {
			chain.doFilter(request, response);
			return;
		}

		String sso_inactive = (String) session.getAttribute("SSO_INACTIVE");
		if (sso_inactive == null || "".equals(sso_inactive) || "0".equals(sso_inactive)) {
			chain.doFilter(request, response);
			return;
		}

		Long last_active_time = (Long) session.getAttribute("SSO_SESSTIME");
		if (last_active_time == null || last_active_time == 0l) {
			chain.doFilter(request, response);
			return;
		}

		Long inactive_time = Long.parseLong(sso_inactive);
		Long calc_time = last_active_time + (inactive_time * 60 * 1000);
		Long curr_time = System.currentTimeMillis();
		//System.out.println("### check: " + url + " - " + calc_time + " / " + curr_time);

		if (calc_time < curr_time) {
			Util.setAuditInfo(userId, "AL", "0", "사용자 로그아웃, " + SSOConfig.getInstance().getServerName());
			String ssopath = SSOConfig.getInstance().getSsoPath();

			if (SSOConfig.getInstance().getSessionSLO())
				httpresponse.sendRedirect(ssopath + "/Logout.jsp?slo=y");
			else
				httpresponse.sendRedirect(ssopath + "/Logout.jsp?slo=n");

			return;
		}
		else {
			index = url.indexOf("checkDupLogin.jsp");
			if (index == -1) {
				session.setAttribute("SSO_SESSTIME", curr_time);
				//System.out.println("### set: " + url + " - " + curr_time);
			}

			chain.doFilter(request, response);
		}
	}

	public void destroy()
	{
		try {
			CryptoApi crypto = CryptoApiFactory.getCryptoApi();
			crypto.clearKey();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}