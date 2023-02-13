<%@ page language="java" contentType="text/html; charset=UTF-8"  pageEncoding="UTF-8"%>
<%@ page import="java.util.ArrayList"%>
<%@ page import="com.dreamsecurity.sso.agent.metadata.MetaGeneratorSP"%>
<%
	String idpId = request.getParameter("idpid") == null ? "" : request.getParameter("idpid");
	String idpLogout = request.getParameter("idplogout") == null ? "" : request.getParameter("idplogout");
	String idpRequest = request.getParameter("idprequest") == null ? "" : request.getParameter("idprequest");
	String spId = request.getParameter("spid") == null ? "" : request.getParameter("spid");
	String spLogout = request.getParameter("splogout") == null ? "" : request.getParameter("splogout");
	String spResponse = request.getParameter("spresponse") == null ? "" : request.getParameter("spresponse");
	String result = "";

	if (idpId.equals("") || idpLogout.equals("") || idpRequest.equals("") ||
			spId.equals("") || spLogout.equals("") || spResponse.equals("")) {
		result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-2,\"resultdata\":\"Prameter Error.\"}]}";
	}
	else {
	    ArrayList<String> idpList = new ArrayList<String>();
	    idpList.add(idpId);
	    idpList.add(idpRequest);
	    idpList.add(idpLogout);

		ArrayList<Object> spTotal = new ArrayList<Object>();
	    ArrayList<String> spList = new ArrayList<String>();
	    spList.add(spId);
	    spList.add(spResponse);
	    spList.add(spLogout);
	    spTotal.add(spList);
	    
	    MetaGeneratorSP spMetaGen = new MetaGeneratorSP();
	    int rtn = spMetaGen.apply(idpList, spTotal);

	    if (rtn == 1) {
	    	result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
	    }
    	else {
	    	result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-1,\"resultdata\":\"Exception Error.\"}]}";
    	}
	}

	response.getWriter().write(result);
%>