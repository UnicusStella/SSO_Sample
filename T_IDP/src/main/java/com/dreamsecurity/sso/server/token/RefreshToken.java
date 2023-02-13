package com.dreamsecurity.sso.server.token;

import com.dreamsecurity.sso.lib.jsn.JSONObject;
import com.dreamsecurity.sso.server.common.MStatus;
import com.dreamsecurity.sso.server.util.OIDCUtil;
import com.dreamsecurity.sso.server.util.Util;

public class RefreshToken
{
	public static final String TOKEN_TYPE = MStatus.REFRESH_TOKEN_TYPE;

	private String jti;    // token id
	private String iss;    // 발급자
	private String sub;    // user_uid
	private String typ;    // token 종류
	private String sid;    // session id
	private String aud;    // 발급받는 client id
	private long exp;      // 만료시간
	private long iat;      // 발생시간
	private String nonce;
	private String acr;

	public RefreshToken(String sub, String sid, String iss, String aud, long iat, long exp, String nonce, String acr)
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
	}

	public RefreshToken(JSONObject refreshTokenJson)
	{
		this.iat = Long.parseLong(refreshTokenJson.get("iat").toString());
		this.jti = (String) refreshTokenJson.get("jti");
		this.iss = (String) refreshTokenJson.get("iss");
		this.sub = (String) refreshTokenJson.get("sub");
		this.typ = (String) refreshTokenJson.get("typ");
		this.sid = (String) refreshTokenJson.get("sid");
		this.aud = (String) refreshTokenJson.get("aud");
		this.nonce = (String) refreshTokenJson.get("nonce");
		this.acr = (String) refreshTokenJson.get("acr");
		this.exp = Long.parseLong(refreshTokenJson.get("exp").toString());
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

		return dataJson.toJSONString();
	}

	public String getJti()
	{
		return jti;
	}

	public String getIss()
	{
		return iss;
	}

	public String getSub()
	{
		return sub;
	}

	public String getTyp()
	{
		return typ;
	}

	public String getSid()
	{
		return sid;
	}

	public String getAud()
	{
		return aud;
	}

	public long getExp()
	{
		return exp;
	}

	public long getIat()
	{
		return iat;
	}

	public String getNonce()
	{
		return nonce;
	}

	public String getAcr()
	{
		return acr;
	}
}