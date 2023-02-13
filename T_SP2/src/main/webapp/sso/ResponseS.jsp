<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.Map"%>
<%@ page import="java.util.HashMap"%>
<%@ page import="com.dreamsecurity.sso.lib.jsn.JSONObject"%>
<%@ page import="com.dreamsecurity.sso.agent.common.MStatus"%>
<%@ page import="com.dreamsecurity.sso.agent.config.*"%>
<%@ page import="com.dreamsecurity.sso.agent.exception.SSOException"%>
<%@ page import="com.dreamsecurity.sso.agent.provider.ServiceProvider"%>
<%@ page import="com.dreamsecurity.sso.agent.token.SSOToken"%>
<%@ page import="com.dreamsecurity.sso.agent.util.Util"%>
<%@ include file="./commonM.jsp"%>
<%
	out.clear();
	pageContext.pushBody();

	SSOConfig.setHomeDir(this.getServletConfig().getServletContext(), DEFAULT_SET_PATH);
	SSOInit.initialize();

	try {
		Map sessionAttrMap = new HashMap();
		sessionAttrMap.put(SSOToken.PROP_NAME_ID, "SSO_ID");
		sessionAttrMap.put(SSOToken.PROP_NAME_NAME, "SSO_NAME");

		JSONObject result = ServiceProvider.getInstance().getResponseData(request, sessionAttrMap);

		if (result == null) {
			Util.sendErrorURL(response, ERROR_URL, "6912", "SP: ResponseS result null", DEFAULT_BASE_URL);
			return;
		}

		if (Integer.parseInt((String) result.get("code")) != MStatus.SUCCESS) {
			Util.sendErrorURL(response, ERROR_URL, (String) result.get("code"), (String) result.get("message"), DEFAULT_BASE_URL);
			return;
		}

		Util.sendURL(response, (String) result.get("data"));
	}
	catch (Exception e) {
		Util.sendErrorURL(response, ERROR_URL, "6913", "SP ResponseS Exception: " + e.getMessage(), DEFAULT_BASE_URL);
	}
%>