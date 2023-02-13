package com.dreamsecurity.sso.server.api.admin.service;

import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;

import com.dreamsecurity.sso.server.config.SSOConfig;
import com.dreamsecurity.sso.server.util.Util;

public class AdminUnlock implements Runnable
{
	private static Logger log = LoggerFactory.getLogger(AdminUnlock.class);

	private String id;
	private long unlockTime;
	private int interval;

	public AdminUnlock(String id, int interval)
	{
		this.id = id;
		this.unlockTime = System.currentTimeMillis() + (interval * 60 * 1000);
		this.interval = interval;
	}

	public void run()
	{
		if (Util.isEmpty(this.id) || interval <= 0) {
			log.error("AdminUnlock Data Empty : id = {}, interval = {}", this.id, this.interval);
			return;
		}

		while (true) {
			try {
				Thread.sleep(1000);
			}
			catch (InterruptedException e) {
				e.printStackTrace();
			}

			long curTime = System.currentTimeMillis();

			if (curTime > unlockTime) {
				AdminService admin = new AdminService();

				try {
					admin.setAdminUnlock(this.id);
				}
				catch (Exception e) {
					admin.setAuditInfo(Util.getDateFormat("yyyyMMdd"), Util.getDateFormat("HHmmss"), SSOConfig.getInstance().getServerName(),
							"AQ", "1", "관리자:" + id);
					e.printStackTrace();
				}

				break;
			}
			else {
				continue;
			}
		}

		return;
	}
}