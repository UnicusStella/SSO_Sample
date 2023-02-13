package com.dreamsecurity.sso.agent.config;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

import com.dreamsecurity.sso.agent.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.agent.util.Util;

public class InitServlet extends HttpServlet
{
	private static final long serialVersionUID = -1384371495142640597L;

	public void init(ServletConfig config) throws ServletException
	{
		super.init(config);

		try {
			String home = getInitParameter("ssohome");
			String audit1 = Util.getDateFormat("yyyyMMdd");
			String audit2 = Util.getDateFormat("HHmmss");

			SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), home);

			SSOCryptoApi crypto = SSOCryptoApi.getInstance();

			Util.setAuditInfo(audit1, audit2, SSOConfig.getInstance().getServerName(), "AA", "0", "시작, " + Util.getServerIP());
			crypto.setInitCryptoAuditInfo();
			crypto.startSsoIntegrity();
			crypto.startSsoProcess();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void destroy()
	{
	}
}