package com.dreamsecurity.sso.agent.dup;

import java.util.HashMap;
import java.util.Map;

import com.dreamsecurity.sso.agent.common.MStatus;
import com.dreamsecurity.sso.agent.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.agent.util.Util;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.jsn.parser.JSONParser;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;

public class DupClient
{
	private static Logger log = LoggerFactory.getLogger(DupClient.class);

	private static String FLAG = "^@^";

	public static String checkLogin(String userId, String userIp, String userBr)
	{
		if (Util.isEmpty(userId) || Util.isEmpty(userIp)) {
			log.error("### DupClient.checkLogin(): Empty parameter");
			return "SUC";
		}

		return checkLogin("dream", userId, userIp, userBr);
	}

	public static String checkLogin(String groupId, String userId, String userIp, String userBr)
	{
		String result = "SUC";

		Map<String, String> param = new HashMap<String, String>();
		param.put("group", groupId);
		param.put("uid", userId);
		param.put("uip", userIp);
		param.put("ubr", userBr);

		String rcvData = DupManager.getInstance().checkLogin(param);

		if (rcvData != null && rcvData.indexOf("DPMS000000041000") >= 0) {
			int idx = rcvData.indexOf(FLAG);
			String msg = rcvData.substring(idx + FLAG.length());
			result = "DUP" + msg.replace(FLAG, " / ");
		}

		// forced logout
		if (rcvData != null && rcvData.indexOf("DPMS000000042000") >= 0) {
			result = "OUT";
		}

		return result;
	}

	public static JSONObject checkLoginC(String encData)
	{
		JSONObject result = new JSONObject();

		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			String decData = new String(crypto.decryptSym(encData));

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(decData);

			String group = (String) jsonData.get("group");
			String id = (String) jsonData.get("id");
			String device = (String) jsonData.get("device");
			String browser = (String) jsonData.get("browser");

			if (Util.isEmpty(group) || Util.isEmpty(id) || Util.isEmpty(device)) {
				result.put("code", String.valueOf(6805));
				result.put("message", "SP checkLoginC: Invalid Parameter");
				result.put("data", "");
				return result;
			}

			if (Util.isEmpty(browser)) {
				browser = "CS";
			}

			Map<String, String> param = new HashMap<String, String>();
			param.put("group", group);
			param.put("uid", id);
			param.put("uip", device);
			param.put("ubr", browser);

			String rcvData = DupManager.getInstance().checkLogin(param);

			if (rcvData != null && rcvData.indexOf("DPMS000000041000") >= 0) {
				int idx = rcvData.indexOf(FLAG);
				String msg = rcvData.substring(idx + FLAG.length());
				msg = msg.replace(FLAG, " / ");
				//log.error("### DupInfo: {}", msg);

				byte[] byteData = crypto.encryptSym(msg.getBytes("EUC-KR"));
				String enc64Data = Util.encode64(byteData);

				result.put("code", String.valueOf(MStatus.FAIL));
				result.put("message", "SP checkLoginC: Duplicate Login");
				result.put("data", enc64Data);
			}
			else if (rcvData != null && rcvData.indexOf("DPMS000000042000") >= 0) {
				result.put("code", String.valueOf(-2));
				result.put("message", "SP checkLoginC: Forced Logout");
				result.put("data", "");
			}
			else {
				result.put("code", String.valueOf(MStatus.SUCCESS));
				result.put("message", "SUCCESS");
				result.put("data", "");
			}
		}
		catch (Exception e) {
			result = null;
			result = new JSONObject();
			result.put("code", String.valueOf(6806));
			result.put("message", "SP checkLoginC Exception: " + e.getMessage());
			result.put("data", "");

			e.printStackTrace();
		}

		return result;
	}

	public static void setPreLoginOut(String userId, String userIp, String userBr)
	{
		if (Util.isEmpty(userId) || Util.isEmpty(userIp)) {
			log.error("### DupClient.setPreLoginOut(): Empty parameter");
			return;
		}

		setPreLoginOut("dream", userId, userIp, userBr);
		return;
	}

	public static void setPreLoginOut(String groupId, String userId, String userIp, String userBr)
	{
		Map<String, String> param = new HashMap<String, String>();
		param.put("group", groupId);
		param.put("uid", userId);
		param.put("uip", userIp);
		param.put("ubr", userBr);

		DupProcess dupThread = null;

		try {
			dupThread = new DupProcess(param, DupManager.FLAG_SET_PRELOGIN_OUT);
			dupThread.start();
		}
		catch (Exception e) {
			if (dupThread != null)  dupThread.interrupt();

			log.error("### DupClient.setPreLoginOut(): {}", e.toString());
			e.printStackTrace();
		}

		return;
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
			case DupManager.FLAG_SET_PRELOGIN_OUT:
				DupManager.getInstance().setPreLoginOut(param);
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