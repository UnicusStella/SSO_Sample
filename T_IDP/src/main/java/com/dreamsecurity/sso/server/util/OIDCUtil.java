package com.dreamsecurity.sso.server.util;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Iterator;
import java.util.UUID;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.lib.slf.Logger;
import com.dreamsecurity.sso.lib.slf.LoggerFactory;


public class OIDCUtil
{
	private static Logger log = LoggerFactory.getLogger(Util.class);

	public static String generateUUID()
	{
		UUID uudi = UUID.randomUUID();
		return uudi.toString();
	}

	public static String base64ToBase64url(String input)
	{
		String output = input.replace("+", "-").replace("/", "_").replace("=", "");
		return output;
	}

	public static String base64urlToBase64(String input)
	{
		String output = input.replace("-", "+").replace("_", "/");
		int i = 0;
		int count = output.length() % 4;

		if (count != 0) {
			for (i = 4; i > count; i--) {
				output = output + "=";
			}
		}

		return output;
	}

	public static String generateRedirectUrl(String redirectUrl, JSONObject parameters)
	{
		Iterator<String> iterator = parameters.keySet().iterator();
		StringBuffer addParam = new StringBuffer();
		String url = redirectUrl;

		while (iterator.hasNext()) {
			String name = (String) iterator.next();
			String value = (String) parameters.get(name);

			try {
				value = URLEncoder.encode(value, "UTF-8");
			}
			catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}

			if (addParam.length() > 0) {
				addParam.append("&");
			}

			addParam.append(name).append("=").append(value);
		}

		if (!Util.isEmpty(addParam.toString())) {
			int index = url.indexOf("?");

			if (index == -1) {
				url = url + "?" + addParam.toString();
			}
			else {
				url = url + "&" + addParam.toString();
			}
		}

		return url;
	}

	public static String generateBaseUrl(HttpServletRequest request)
	{
		String baseUrl = "";
		String accessUrl = request.getRequestURL().toString();
		String accessUri = request.getRequestURI();
		baseUrl = accessUrl.substring(0, accessUrl.length()-accessUri.length());

		return baseUrl;
	}
}