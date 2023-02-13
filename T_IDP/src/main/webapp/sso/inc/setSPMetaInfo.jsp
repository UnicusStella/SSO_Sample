<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.ArrayList"%>
<%@ page import="java.util.List"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.metadata.IDPSSODescriptor"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.metadata.SPSSODescriptor"%>
<%@ page import="com.dreamsecurity.sso.server.metadata.MetadataRepository"%>
<%@ page import="com.dreamsecurity.sso.server.metadata.MetaGeneratorIDP"%>
<%
	String idpId = request.getParameter("idpid") == null ? "" : request.getParameter("idpid");
	String idpLogout = request.getParameter("idplogout") == null ? "" : request.getParameter("idplogout");
	String idpRequest = request.getParameter("idprequest") == null ? "" : request.getParameter("idprequest");
	String spId = request.getParameter("spid") == null ? "" : request.getParameter("spid");
	String spLogout = request.getParameter("splogout") == null ? "" : request.getParameter("splogout");
	String spResponse = request.getParameter("spresponse") == null ? "" : request.getParameter("spresponse");
	String result = "";

	if (spId.equals("") || spLogout.equals("") || spResponse.equals("")) {
		result = "setMeta({\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-2,\"resultdata\":\"Parameter Error.\"}]});";
	}
	else {
		MetadataRepository metaInstance = MetadataRepository.getInstance();
		IDPSSODescriptor idpDescriptor = MetadataRepository.getInstance().getIDPDescriptor();
		List<String> spIdList = metaInstance.getSPNames();
		ArrayList<String> idpList = new ArrayList<String>();
		ArrayList<Object> spTotal = new ArrayList<Object>();

		if (idpId.equals("")) {
			idpList.add(metaInstance.getIDPName());
			idpList.add(idpDescriptor.getSingleSignOnServices().get(0).getLocation());
			idpList.add(idpDescriptor.getSingleLogoutServices().get(0).getLocation());
		}
		else {
			idpList.add(idpId);
			idpList.add(idpRequest);
			idpList.add(idpLogout);
		}

		boolean updateFlag = false;

		for (int j = (spIdList.size() - 1); j >= 0; j--) {
			ArrayList<String> spList = new ArrayList<String>();

			if (spId.equals(spIdList.get(j))) {
				spList.add(spId);
				spList.add(spResponse);
				spList.add(spLogout);
				updateFlag = true;
			}
			else {
				SPSSODescriptor spDescriptor = metaInstance.getSPDescriptor(spIdList.get(j));
				int spServiceCount = spDescriptor.getAssertionConsumerServices().size();

				spList.add(spIdList.get(j));

				String orgResponse = "";
				String orgLogout = "";
				for (int i = 0; i < spServiceCount; i++) {
					orgResponse += spDescriptor.getAssertionConsumerServices().get(i).getLocation() + "^";
					orgLogout += spDescriptor.getSingleLogoutServices().get(i).getLocation() + "^";
				}

				spList.add(orgResponse);
				spList.add(orgLogout);
			}

			spTotal.add(spList);
		}

		if (!updateFlag) {
			ArrayList<String> spList = new ArrayList<String>();
			spList.add(spId);
			spList.add(spResponse);
			spList.add(spLogout);

			spTotal.add(spList);
		}

		MetaGeneratorIDP idpMetaGen = new MetaGeneratorIDP();
		int rtn = idpMetaGen.apply(idpList, spTotal);

		if (rtn == 1) {
			result = "setMeta({\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]});";
		}
		else {
			result = "setMeta({\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-1,\"resultdata\":\"Exception Error.\"}]});";
		}
	}

	response.getWriter().write(result);
%>