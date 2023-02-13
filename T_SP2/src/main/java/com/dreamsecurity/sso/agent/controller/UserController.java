package com.dreamsecurity.sso.agent.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.rmi.ServerException;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.dreamsecurity.sso.agent.api.UserService;
import com.dreamsecurity.sso.agent.common.MStatus;
import com.dreamsecurity.sso.agent.config.SSOConfig;
import com.dreamsecurity.sso.agent.crypto.SSOCryptoApi;
import com.dreamsecurity.sso.agent.util.Util;
import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.jsn.parser.JSONParser;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;

@WebServlet(urlPatterns = "/user/*")
public class UserController extends HttpServlet
{
	private static final long serialVersionUID = 1L;

	private static Logger log = LoggerFactory.getLogger(UserController.class);

	@Override
	protected void service(HttpServletRequest request, HttpServletResponse response) throws ServerException, IOException
	{
		response.setHeader("Cache-Control", "no-cache");

		SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), "/WEB-INF/dreamsso");
		request.setAttribute("loginBr", Util.getBrowserType(request));

		if (request.getRequestURI().indexOf("/user/") != 0) {
			response.setStatus(404);
			return;
		}

		String subpath = request.getRequestURI().substring("/user/".length());

		if ("info/check".equals(subpath)) {
			userPwCheck(request, response);
		}
		else {
			response.setStatus(404);
			return;
		}
	}

	private void userPwCheck(HttpServletRequest request, HttpServletResponse response)
	{
		JSONObject result = null;

		String encData = request.getParameter("ED") == null ? "" : request.getParameter("ED");

		if (Util.isEmpty(encData)) {
			result = new JSONObject();
			result.put("code", String.valueOf(8598));
			result.put("message", "SP: userPwCheck parameter is Empty");
			result.put("data", "");

			sendResponse(response, result);
			return;
		}

		try {
			SSOCryptoApi crypto = SSOCryptoApi.getInstance();
			String decData = new String(crypto.decryptSym(encData));

			JSONParser parser = new JSONParser();
			JSONObject jsonData = (JSONObject) parser.parse(decData);

			String uid = (String) jsonData.get("id");
			String upw = (String) jsonData.get("pw");

			if (Util.isEmpty(uid) || Util.isEmpty(upw)) {
				result = new JSONObject();
				result.put("code", String.valueOf(8597));
				result.put("message", "SP: userPwCheck parameter is Empty");
				result.put("data", "");

				sendResponse(response, result);
				return;
			}

			result = UserService.checkPw(uid, upw);

			if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
				log.error("### userPwCheck: {}, {}", (String) result.get("code"), (String) result.get("message"));

				sendResponse(response, result);
				return;
			}
		}
		catch (Exception e) {
			log.error("### userPwCheck Exception: {}", e.getMessage());
			e.printStackTrace();

			result = new JSONObject();
			result.put("code", String.valueOf(8599));
			result.put("message", "SP: userPwCheck Exception: " + e.getMessage());
			result.put("data", "");
		}

		sendResponse(response, result);
		return;
	}

	public void sendResponse(HttpServletResponse response,JSONObject result)
	{
		try {
			response.setStatus(200);
			response.setHeader("Content-Type", "application/json; charset=UTF-8");

			PrintWriter out = response.getWriter();
			out.write(result.toString());
			out.flush();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return;
	}
}