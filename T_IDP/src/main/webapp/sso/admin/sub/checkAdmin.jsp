<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page import="java.util.Calendar"%>
<%@ page import="java.util.Date"%>
<%@ page import="java.util.Map"%>
<%@ page import="com.dreamsecurity.sso.server.config.SSOConfig"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%
	String adminid = "";
	String adminname = "";
	String admintype = "";
	String adminip = "";
	String adminmenu = "";
	String adminfirst = "";
	String adminsalt = "";
	String adminidle = "";
	String currip = Util.getClientIP(request);

	Map<?,?> adminMap = (Map<?,?>) session.getAttribute("SSO_ADMIN_INFO");
	if (adminMap != null) {
		adminid = (String) adminMap.get("id");
		adminname = (String) adminMap.get("name");
		admintype = (String) adminMap.get("admnType");
		adminip = (String) adminMap.get("admnIp");
		adminmenu = (String) adminMap.get("admnMenu");
		adminfirst = (String) adminMap.get("admnFirst");
		adminsalt = (String) adminMap.get("admnSalt");
		adminidle = (String) adminMap.get("sessionTime");
	}
%>
<%!
	public String checkAdmin(String adminid, String admintype, String adminmenu, String code)
	{
		String result = "";

		if (adminid.equals("")) {
			result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-9,\"resultdata\":\"\"}]}";
			return result;
		}
	
		if (admintype.equals("N")) {
			if (adminmenu == null)
				result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-8,\"resultdata\":\"\"}]}";

			int index = adminmenu.indexOf(code);
			if (index == -1)
				result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-8,\"resultdata\":\"\"}]}";
		}
		else {
		}

		return result;
	}

	public boolean checkAdminCSRFToken(HttpServletRequest request)
	{
		HttpSession session = request.getSession(false);

		String ch = request.getParameter("ch") == null ? "" : request.getParameter("ch");
		String sessionCh = session.getAttribute("APCHLG") == null ? "" : (String) session.getAttribute("APCHLG");
		Date sessionTm = (Date) session.getAttribute("APTIME");

		if (Util.isEmpty(ch)) {
			return false;
		}

		if (sessionTm != null) {
			Date curDate = new Date(System.currentTimeMillis());
			Calendar cal = Calendar.getInstance();
			cal.setTime(sessionTm);
			cal.add(Calendar.MINUTE, SSOConfig.getInstance().getAdminCSRFTokenTime());
			sessionTm = cal.getTime();

			int compare = curDate.compareTo(sessionTm);
			if (compare > 0) {
				session.removeAttribute("APCHLG");
				session.removeAttribute("APTIME");
				return false;
			}
			else {
				if (Util.isEmpty(sessionCh) || !sessionCh.equals(ch)) {
					return false;
				}
			}
		}
		else {
			sessionCh = "";
			return false;
		}

		session.setAttribute("APTIME", new Date());
		return true;
	}
%>