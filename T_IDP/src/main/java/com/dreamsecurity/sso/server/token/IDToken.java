package com.dreamsecurity.sso.server.token;

import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.util.OIDCUtil;
import com.dreamsecurity.sso.server.util.Util;

public class IDToken
{
	public static final String TOKEN_TYPE = MStatus.ID_TOKEN_TYPE;

	private String jti;      // token id
	private String iss;      // 발급자
	private String sub;      // user_uid
	private String typ;      // token 종류
	private String sid;      // session id
	private String aud;      // 발급받는 client id
	private long exp;
	private long iat;        // 발생시간
	private String nonce;
	private String acr;
	private String at_hash;
	private long auth_time;
	private String name;     // user_name
	private String email;    // user_email


	public IDToken(String sub, String sid, String name, String email, String iss, String aud, long iat, long exp, String nonce, String acr, String at_hash, long auth_time)
	{
		this.iat = iat;
		this.jti = OIDCUtil.generateUUID();
		this.iss = iss;
		this.sub = sub;
		this.typ = TOKEN_TYPE;
		this.sid = sid;
		this.aud = aud;
		this.nonce = nonce;
		this.acr = acr;
		this.exp = exp;
		this.at_hash = at_hash;
		this.auth_time = auth_time;
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
		dataJson.put("aud", aud);
		dataJson.put("exp", exp);

		if (!Util.isEmpty(nonce)) {
			dataJson.put("nonce", nonce);
		}

		dataJson.put("acr", acr);
		dataJson.put("at_hash", at_hash);
		dataJson.put("auth_time", auth_time);
		dataJson.put("name", name);
		dataJson.put("email", email);

		return dataJson.toJSONString();
	}
}