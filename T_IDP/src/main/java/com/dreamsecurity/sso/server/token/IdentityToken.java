package com.dreamsecurity.sso.server.token;

import java.util.Date;

import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.util.OIDCUtil;

public class IdentityToken
{
	public static final String TOKEN_TYPE = MStatus.IDENTITY_TOKEN_TYPE;

	private long iat;     // 발생시간
	private String jti;   // token id
	private String iss;   // 발급자
	private String sub;   // user_uid
	private String typ;   // token 종류
	private String sid;   // session id
	private String name;  // user_name
	private String email; // user_email

	public IdentityToken(String sub, String sid, String name, String email, String iss, Date curDate)
	{
		this.iat = curDate.getTime() / 1000;
		this.jti = OIDCUtil.generateUUID();
		this.iss = iss;
		this.sub = sub;
		this.typ = TOKEN_TYPE;
		this.sid = sid;
		this.name = name;
		this.email = email;
	}

	public String tokenToJsonString()
	{
		JSONObject dataJson = new JSONObject();
		dataJson.put("iat", iat);
		dataJson.put("jti", jti);
		dataJson.put("iss", iss);
		dataJson.put("sub", sub);
		dataJson.put("typ", typ);
		dataJson.put("sid", sid);
		dataJson.put("name", name);
		dataJson.put("email", email);

		return dataJson.toJSONString();
	}
}