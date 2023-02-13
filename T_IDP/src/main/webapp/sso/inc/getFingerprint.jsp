<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="com.dreamsecurity.sso.server.config.SSOConfig"%>
<%@ page import="com.dreamsecurity.sso.server.crypto.SSOCryptoApi"%>
<%@ page import="com.dreamsecurity.jcaos.util.FileUtil"%>
<%@ page import="com.dreamsecurity.jcaos.util.encoders.Hex"%>
<%
	SSOConfig conf = SSOConfig.getInstance();
	String path = conf.getHomePath(conf.getCertSignpath());
	path = path.replaceAll(".key", ".der");
	String hashVal = new String(Hex.encode(SSOCryptoApi.getInstance().hash(FileUtil.read(path), "SHA1")));

	StringBuffer fingerprint = new StringBuffer();

	for (int i = 0; i < hashVal.length(); i += 2) {
		if (i != 0)  fingerprint.append(":");
		fingerprint.append(hashVal.substring(i, i+2));
	}

	out.println(fingerprint.toString());
%>