<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ page session="true"%>
<%@ page import="java.util.Calendar"%>
<%@ page import="java.util.Date"%>
<%@ page import="java.util.Map"%>
<%@ page import="com.dreamsecurity.sso.server.config.SSOConfig"%>
<%@ page import="com.dreamsecurity.sso.server.util.Util"%>
<%
	String DEFAULT_SET_PATH = "/WEB-INF/classes";
%>
<%!
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
	
		return true;
	}
%>