package com.dreamsecurity.sso.server.dup;

import java.util.HashMap;
import java.util.Map;

import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;
import com.dreamsecurity.sso.server.util.Util;

public class DupClient
{
	private static Logger log = LoggerFactory.getLogger(DupClient.class);

	public static void putLogin(String userId, String userIp, String userBr)
	{
		if (Util.isEmpty(userId) || Util.isEmpty(userIp)) {
			log.error("### DupClient.putLogin(): Empty parameter");
			return;
		}

		putLogin("dream", userId, userIp, userBr);
		return;
	}

	public static void putLogin(String groupId, String userId, String userIp, String userBr)
	{
		Map<String, String> param = new HashMap<String, String>();
		param.put("group", groupId);
		param.put("uid", userId);
		param.put("uip", userIp);
		param.put("ubr", userBr);

		DupProcess dupThread = null;

		try {
			dupThread = new DupProcess(param, DupManager.FLAG_PUT_LOGIN);
			dupThread.start();
		}
		catch (Exception e) {
			if (dupThread != null)  dupThread.interrupt();

			log.error("### DupClient.putLogin(): {}", e.toString());
			e.printStackTrace();
		}

		return;
	}

	public static void putLogout(String groupId, String userId)
	{
		Map<String, String> param = new HashMap<String, String>();
		param.put("group", groupId);
		param.put("uid", userId);

		DupProcess dupThread = null;

		try {
			dupThread = new DupProcess(param, DupManager.FLAG_PUT_LOGOUT);
			dupThread.start();
		}
		catch (Exception e) {
			if (dupThread != null)  dupThread.interrupt();

			log.error("### DupClient.putLogout(): {}", e.toString());
			e.printStackTrace();
		}

		return;
	}

	public static String getPreLogin(String userId, String userIp, String userBr)
	{
		if (Util.isEmpty(userId) || Util.isEmpty(userIp)) {
			log.error("### DupClient.getPreLogin(): Empty parameter");
			return "";
		}

		
		return getPreLogin("dream", userId, userIp, userBr);
	}

	public static String getPreLogin(String groupId, String userId, String userIp, String userBr)
	{
		String result = "";

		Map<String, String> param = new HashMap<String, String>();
		param.put("group", groupId);
		param.put("uid", userId);
		param.put("uip", userIp);
		param.put("ubr", userBr);

		String rcvData = DupManager.getInstance().getPreLogin(param);

		// DPMS00060000000100000000.....
		if (rcvData != null && rcvData.length() > 24) {
			result = rcvData.substring(24);
		}

		return result;
	}
}

class DupProcess extends Thread
{
	private static Logger log = LoggerFactory.getLogger(DupProcess.class);

	Map<String, String> param;
	int procType;

	DupProcess(Map<String, String> param, int procType)
	{
		this.param = param;
		this.procType = procType;
	}

	public void run()
	{
		try {
			switch (this.procType) {
			case DupManager.FLAG_PUT_LOGIN:
				DupManager.getInstance().putLogin(param);
				break;

			case DupManager.FLAG_PUT_LOGOUT:
				DupManager.getInstance().putLogout(param);
				break;
			}
		}
		catch (Exception e) {
			log.debug("### DupProcess Data: {}, {}", procType, param.toString());
			log.error("### DupProcess Exception: {}", e.toString());
			e.printStackTrace();
		}
	}
}