package com.dreamsecurity.sso.server.config;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

import com.dreamsecurity.sso.server.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.server.ha.SyncMonitor;
import com.dreamsecurity.sso.server.provider.EnvironInform;
import com.dreamsecurity.sso.server.repository.RepositoryApiFactory;
import com.dreamsecurity.sso.server.repository.connection.DBConnectMap;
import com.dreamsecurity.sso.server.repository.ldap.pool.LdapPoolLoader;
import com.dreamsecurity.sso.server.util.Util;

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

			new RepositoryApiFactory().createRepository();

			EnvironInform envInform = EnvironInform.getInstance();

			Util.setAuditInfo(audit1, audit2, SSOConfig.getInstance().getServerName(), "AA", "0", "시작, " + Util.getServerIP());
			crypto.setInitCryptoAuditInfo();

			int rtn = crypto.startSsoIntegrity();
			if (rtn != 0) {
				Util.sendMail("MSND0001", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), SSOConfig.getInstance().getServerName(), "");
			}

			rtn = crypto.startSsoProcess();
			if (rtn != 0) {
				Util.sendMail("MSND0005", Util.getDateFormat("yyyy-MM-dd  HH:mm:ss"), SSOConfig.getInstance().getServerName(), "");
			}

			SyncMonitor.startMonitor();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void destroy()
	{
		if (SSOConfig.getInstance().getString("repository[@type]").equalsIgnoreCase("DB")) {
			DBConnectMap.getInstance().stopConnectionMonitor();
		}
		else {
			LdapPoolLoader.getInstance().stopConnectionMonitor();
		}
	}
}