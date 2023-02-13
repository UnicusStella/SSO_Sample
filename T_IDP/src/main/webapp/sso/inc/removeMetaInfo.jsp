<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.util.ArrayList"%>
<%@ page import="java.util.List"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.metadata.IDPSSODescriptor"%>
<%@ page import="com.dreamsecurity.sso.lib.dss.s2.metadata.SPSSODescriptor"%>
<%@ page import="com.dreamsecurity.sso.server.metadata.MetadataRepository"%>
<%@ page import="com.dreamsecurity.sso.server.metadata.MetaGeneratorIDP"%>
<%
	String spId = request.getParameter("spid") == null ? "" : request.getParameter("spid");
	String result = "";

	if (spId.equals("")) {
		result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-2,\"resultdata\":\"Parameter Error.\"}]}";
	}
	else {
		MetadataRepository metaInstance = MetadataRepository.getInstance();
		IDPSSODescriptor idpDescriptor = MetadataRepository.getInstance().getIDPDescriptor();
		List<String> spIdList = metaInstance.getSPNames();
		ArrayList<String> idpList = new ArrayList<String>();
		ArrayList<Object> spTotal = new ArrayList<Object>();

		idpList.add(metaInstance.getIDPName());
		idpList.add(idpDescriptor.getSingleSignOnServices().get(0).getLocation());
		idpList.add(idpDescriptor.getSingleLogoutServices().get(0).getLocation());

		for (int j = (spIdList.size() - 1); j >= 0; j--) {
			ArrayList<String> spList = new ArrayList<String>();

			if (spId.equals(spIdList.get(j))) {
				continue;
			}
			else {
				SPSSODescriptor spDescriptor = metaInstance.getSPDescriptor(spIdList.get(j));
				int spServiceCount = spDescriptor.getAssertionConsumerServices().size();

				spList.add(spIdList.get(j));

				String orgResponse = "";
				String orgLogout = "";
				for (int i = 0; i < spServiceCount; i++) {
					orgResponse += spDescriptor.getAssertionConsumerServices().get(i).getLocation() + ">";
					orgLogout += spDescriptor.getSingleLogoutServices().get(i).getLocation() + ">";
				}

				spList.add(orgResponse);
				spList.add(orgLogout);
			}

			spTotal.add(spList);
		}

		MetaGeneratorIDP idpMetaGen = new MetaGeneratorIDP();
		int rtn = idpMetaGen.apply(idpList, spTotal);

		if (rtn == 1) {
			result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":1,\"resultdata\":\"\"}]}";
		}
		else {
			result = "{\"page\":1,\"total\":1,\"records\":1,\"rows\":[{\"resultstatus\":-1,\"resultdata\":\"Exception Error.\"}]}";
		}
	}

	response.getWriter().write(result);
%>