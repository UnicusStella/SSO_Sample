package com.dreamsecurity.sso.agent.config;

import com.dreamsecurity.sso.agent.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.agent.ha.SyncMonitor;
import com.dreamsecurity.sso.agent.util.Util;

public class SSOInit
{
	public static void initialize()
	{
		if (SSOConfig.getInstance().isSsoInitialize()) {
			return;
		}

		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();

			Util.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"),
					SSOConfig.getInstance().getServerName(), "AA", "0", "시작, " + Util.getServerIP());
			crypto.setInitCryptoAuditInfo();

			crypto.startSsoIntegrity();
			crypto.startSsoProcess();

			SSOConfig.getInstance().setSsoInitialize(true);

			SyncMonitor.startMonitor();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}