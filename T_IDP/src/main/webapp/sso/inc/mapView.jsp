<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.*"%>
<%@ page import="java.util.Map.*"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.core.AuthnRequest"%>
<%@ page import="com.dreamsecurity.sso.lib.jtm.*"%>
<%@ page import="com.dreamsecurity.sso.server.session.*"%>
<%
	String gubun = request.getParameter("gubun") == null ? "1" : (String) request.getParameter("gubun");
	String user = "";
	String prevDay = "";
	int nPrevDay = 0;

	if (gubun.equals("1")) {
		user = request.getParameter("userId") == null ? "" : (String) request.getParameter("userId");
	}
	else if (gubun.equals("2") || gubun.equals("3")) {
		prevDay = request.getParameter("prevDay") == "" ? "0" : (String) request.getParameter("prevDay");
		nPrevDay = Integer.parseInt(prevDay);
	}
%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title></title>
<script type="text/javascript">
function search(gubun)
{
	if (gubun == 3) {
		if (!confirm(" Invalidated 데이터를 SessionMap에서 삭제하시겠습니까?")) {
			return;
		}
	}

	if (gubun == 5) {
		if (!confirm(" Invalidated 데이터를 AuthnMap에서 삭제하시겠습니까?")) {
			return;
		}
	}

	document.ssoSearchForm.gubun.value = gubun;
	document.ssoSearchForm.action = "./mapView.jsp";
	document.ssoSearchForm.submit();
}
</script>
</head>
<body>
<form name="ssoSearchForm" method="post">
	<br>
	<input type="hidden" name="gubun" value="1"/>
	ID&nbsp;&nbsp;&nbsp;<input type='text' name='userId' style='width:200px; height:18px; margin-bottom:10px; padding-left:3px;' size='20' value='<%=user%>'/>&nbsp;
	<input type='button' value='조 회' onClick='search(1);'>
	<br>
	Session_Map : &nbsp;&nbsp;&nbsp;<input type='text' name='prevDay' style='width:38px; height:18px; margin-bottom:10px; text-align:right; padding-right:2px;' size='3' value='<%=prevDay%>'/>&nbsp;&nbsp;일전 자료&nbsp;&nbsp;
	<input type='button' value='조 회' onClick='search(2);'>&nbsp;
	<input type='button' value='삭 제' onClick='search(3);'>
	<br>
	Authn_Map : Invalidated Data&nbsp;&nbsp;&nbsp;<input type='button' style='margin-bottom:10px;' value='삭 제' onClick='search(5);'>
	<br>
	-------------------------------------------------------------------
</form>
<%
	String tab = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";

	Map sessMap = SessionManager.getInstance().getSessionMap();
	Map authnMap = SessionManager.getInstance().getAuthnMap();

	if ((gubun.equals("2") || gubun.equals("3")) && nPrevDay >= 0) {
		Map<String, String> prevMap = new HashMap<String, String>();

		Iterator smKeySet = sessMap.keySet().iterator();
		while (smKeySet.hasNext()) {
			String uid = (String) smKeySet.next();
			ArrayList authList = (ArrayList) sessMap.get(uid);

			for (int i = 0; i < authList.size(); i++) {
				AuthSession authSess = (AuthSession) authList.get(i);
				Map provMap = authSess.getSessionByProvID();

				Iterator provKeySet = provMap.keySet().iterator();
				if (provKeySet.hasNext()) {
					String provId = (String) provKeySet.next();
					RemoteSession remote = (RemoteSession) provMap.get(provId);

					DateTime ztime = new DateTime(DateTimeZone.forID("Asia/Seoul")).minusDays(nPrevDay - 1);
					DateTime baseTime = new DateTime(ztime.getYear(), ztime.getMonthOfYear(), ztime.getDayOfMonth(), 0, 0, 0, 0, DateTimeZone.forID("Asia/Seoul"));
					//DateTime baseTime = new DateTime(2020, 8, 4, 0, 0, DateTimeZone.forID("Asia/Seoul"));
					out.println("<br>baseTime : " + baseTime + "<br>");

					if (baseTime.compareTo(remote.getIssueInstant()) > 0) {
						prevMap.put(uid, provId);
					}
				}
			}
		}

		if (gubun.equals("2")) {
			out.println("<br>Session_Map :&nbsp;&nbsp;" + prevDay + " 일전 자료 &nbsp;&nbsp;" + prevMap.size() + " 건<br>");

			int i = 0;
			Iterator prevKeySet = prevMap.keySet().iterator();
			while (prevKeySet.hasNext() && i < 10) {
				String uid = (String) prevKeySet.next();
				String provId = (String) prevMap.get(uid);
				out.println(tab + uid + " / " + provId + "<br>");
				i++;
			}
		}
		else {  // delete SessionMap
			if (prevMap.size() > 0) {
				int i = 0;
				Iterator prevKeySet = prevMap.keySet().iterator();
				while (prevKeySet.hasNext()) {
					String uid = (String) prevKeySet.next();
					String provId = (String) prevMap.get(uid);

					ArrayList authList = (ArrayList) sessMap.get(uid);

					for (int j = 0; j < authList.size(); j++) {
						AuthSession authSess = (AuthSession) authList.get(j);
						Map provMap = authSess.getSessionByProvID();
						Map contextMap = authSess.getSessionByAuthClass();

						RemoteSession remote = (RemoteSession) provMap.get(provId);

						if (remote != null) {
							DateTime ztime = new DateTime(DateTimeZone.forID("Asia/Seoul")).minusDays(nPrevDay - 1);
							DateTime baseTime = new DateTime(ztime.getYear(), ztime.getMonthOfYear(), ztime.getDayOfMonth(), 0, 0, 0, 0, DateTimeZone.forID("Asia/Seoul"));
							
							if (baseTime.compareTo(remote.getIssueInstant()) > 0) {
								ArrayList remoteList = (ArrayList) contextMap.get(remote.getAuthnContextClassRef());
								if (remoteList != null) {
									remoteList.remove(remote);
								}

								provMap.remove(provId);
								i++;
							}
						}
					}
				}

				// delete empty AuthSession
				Map<String, Object> empMap = new HashMap<String, Object>();
				Iterator smKeySet2 = sessMap.keySet().iterator();

				while (smKeySet2.hasNext()) {
					String uid = (String) smKeySet2.next();
					ArrayList authList = (ArrayList) sessMap.get(uid);

					for (int j = 0; j < authList.size(); j++) {
						AuthSession authSess = (AuthSession) authList.get(j);
						Map provMap = authSess.getSessionByProvID();

						if (provMap.size() == 0) {
							empMap.put(uid, authSess);
						}
					}
				}

				if (empMap.size() > 0) {
					Iterator<String> empKey = empMap.keySet().iterator();

					while (empKey.hasNext()) {
						String uid = (String) empKey.next();
						AuthSession authSess = (AuthSession) empMap.get(uid);

						ArrayList authList = (ArrayList) sessMap.get(uid);
						authList.remove(authSess);
					}
				}

				// delete empty AuthSession List
				empMap.clear();
				Iterator smKeySet3 = sessMap.keySet().iterator();

				while (smKeySet3.hasNext()) {
					String uid = (String) smKeySet3.next();
					ArrayList authList = (ArrayList) sessMap.get(uid);

					if (authList.size() == 0) {
						empMap.put(uid, "");
					}
				}

				if (empMap.size() > 0) {
					Iterator<String> empKey = empMap.keySet().iterator();

					while (empKey.hasNext()) {
						String uid = (String) empKey.next();
						sessMap.remove(uid);
					}
				}

				out.println("<br>Session_Map :&nbsp;&nbsp;" + prevDay + " 일전 자료 :&nbsp;&nbsp;" + i + " 건&nbsp;&nbsp;삭제 완료<br>");
			}
			else {
				out.println("<br>Session_Map :&nbsp;&nbsp;" + prevDay + " 일전 자료 :&nbsp;&nbsp;삭제 대상 없음<br>");
			}
		}
	}

	if (gubun.equals("5")) {
		List<String> delList = new ArrayList<String>();

		Iterator authnKeySet = authnMap.keySet().iterator();
		while (authnKeySet.hasNext()) {
			String spid = (String) authnKeySet.next();
			AuthnRequest authnRequest = (AuthnRequest) authnMap.get(spid);

			DateTime ztime = new DateTime(DateTimeZone.forID("Asia/Seoul"));
			DateTime baseTime = new DateTime(ztime.getYear(), ztime.getMonthOfYear(), ztime.getDayOfMonth(), 0, 0, 0, 0, DateTimeZone.forID("Asia/Seoul"));
			
			if (baseTime.compareTo(authnRequest.getIssueInstant()) > 0) {
				delList.add(spid);
			}
		}

		if (delList.size() > 0) {
			int i = 0;
			Iterator<String> delkey = delList.iterator();

			while (delkey.hasNext()) {
				String spid = (String) delkey.next();
				authnMap.remove(spid);
				i++;
			}

			out.println("<br>Authn_Map :&nbsp;&nbsp;" + i + " 건&nbsp;&nbsp;삭제 완료<br>");
		}
		else {
			out.println("<br>Authn_Map :&nbsp;&nbsp;0 건&nbsp;&nbsp;삭제 완료<br>");
		}
	}

	out.println("<br>Session_Map size = " + sessMap.size() + "<br>");
	Iterator iterator = sessMap.entrySet().iterator();

	while (iterator.hasNext()) {
		Entry sessEntry = (Entry) iterator.next();
		String uid = (String) sessEntry.getKey();
		ArrayList authList = (ArrayList) sessEntry.getValue();

		if (!user.equals(uid))  continue;

		out.println(tab + "key (user) = " + uid + "<br>");
		out.println(tab + "value (AuthSession_List) : size = " + authList.size() + "<br>");

		for (int i = 0; i < authList.size(); i++) {
			out.println(tab + tab + "[" + (i+1) + "] AuthSession<br>");

			AuthSession authSess = (AuthSession) authList.get(i);
			Map sessByProvID = authSess.getSessionByProvID();
			Iterator provIter = sessByProvID.entrySet().iterator();

			if (provIter.hasNext())
				out.println(tab + tab + tab + "SessionByProvID_Map : size = " + sessByProvID.size() + "<br>");

			int j = 1;
			while (provIter.hasNext()) {
				Entry provEntry = (Entry) provIter.next();
				String spid = (String) provEntry.getKey();
				RemoteSession remote = (RemoteSession) provEntry.getValue();

				out.println(tab + tab + tab + tab + "[" + j + "]<br>");
				out.println(tab + tab + tab + tab + "key (SPName) = " + spid + "<br>");
				out.println(tab + tab + tab + tab + "value (RemoteSession) = " + "<br>");

				out.println(tab + tab + tab + tab + tab + "IssueInstant = " + remote.getIssueInstant().toDateTime(DateTimeZone.forID("Asia/Seoul")) + "<br>");
				out.println(tab + tab + tab + tab + tab + "ProvSessionId = " + remote.getProvSessionId() + "<br>");
				out.println(tab + tab + tab + tab + tab + "AuthnContextClassRef = " + remote.getAuthnContextClassRef() + "<br>");
				j++;
			}

			Map sessByAuthClass = authSess.getSessionByAuthClass();
			Iterator authIter = sessByAuthClass.entrySet().iterator();

			if (authIter.hasNext())
				out.println("<br>" + tab + tab + tab + "SessionByAuthClass_Map : size = " + sessByAuthClass.size() + "<br>");

			int k = 1;
			while (authIter.hasNext()) {
				Entry provEntry = (Entry) authIter.next();
				String authClass = (String) provEntry.getKey();
				ArrayList remoteList = (ArrayList) provEntry.getValue();

				out.println(tab + tab + tab + tab + "[" + k + "]<br>");
				out.println(tab + tab + tab + tab + "key (AuthnContextClassRef) = " + authClass + "<br>");
				out.println(tab + tab + tab + tab + "value (RemoteSession_List) : size = " + remoteList.size() + "<br>");
				k++;
			}
		}
	}

	// AuthnMap
	out.println("<br>Authn_Map size = " + authnMap.size() + "<br>");

	Iterator authnKeySet = authnMap.keySet().iterator();
	int jj = 1;

	while (authnKeySet.hasNext()) {
		out.println(tab + "[" + jj + "]<br>");

		String spid = (String) authnKeySet.next();
		DateTime issueTime = (DateTime) authnMap.get(spid);

		out.println(tab + "key (SP_Name + randomNo) = " + spid + "<br>");
		out.println(tab + "value (AuthnRequest) = IssueInstant: " + issueTime.toDateTime(DateTimeZone.forID("Asia/Seoul")) + "<br>");

		jj++;
		//if (jj > 10)  break;
	}
%>
</body>
</html>
