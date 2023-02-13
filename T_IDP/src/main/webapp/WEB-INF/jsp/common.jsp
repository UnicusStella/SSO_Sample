<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%!
	public String getBrowserType(HttpServletRequest request)
	{
		String browser = "";
		String userAgent = request.getHeader("User-Agent").toLowerCase();
		if (userAgent.indexOf("trident") >= 0 || userAgent.indexOf("msie") >= 0) {
			browser = "IE";
		}
		else if (userAgent.indexOf("edg") >= 0) {
			browser = "EG";
		}
		else if (userAgent.indexOf("opr") >= 0 || userAgent.indexOf("opera") >= 0) {
			browser = "OP";
		}
		else if (userAgent.indexOf("chrome") >= 0) {
			browser = "CR";
		}
		else if (userAgent.indexOf("safari") >= 0) {
			browser = "SF";
		}
		else if (userAgent.indexOf("firefox") >= 0) {
			browser = "FF";
		}
		else {
			browser = "NN";
		}
		return browser;
	}

	public String XSSCheck(String value)
	{
		if (value != null && value.trim().length() > 0) {
			value = value.trim();
			value = value.replaceAll("<", "&lt;");
			value = value.replaceAll(">", "&gt;");
			value = value.replaceAll("&", "&amp;");
			value = value.replaceAll("\"", "&quot;");
			value = value.replaceAll("\'", "&apos;");
		}
	
		return value;
	}
%>