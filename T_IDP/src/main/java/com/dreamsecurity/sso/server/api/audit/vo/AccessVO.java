package com.dreamsecurity.sso.server.api.audit.vo;

import java.io.Serializable;
import java.text.DecimalFormat;
import java.text.NumberFormat;

public class AccessVO implements Serializable
{
	private static final long serialVersionUID = 2449928903348046749L;

	/***************
	 * 1. type : cmd 이름 (로그인,연계,로그아웃)
	 * 2. result : 처리결과 (success, failure)
	 * 3. code : 처리코드
	 * 4. userId : 접속 사용자 아이디
	 * 5. macAddr : 접속 사용자 맥어드레스
	 * 7. message : 메시지
	 * 
	 * accessTime 은 로깅시점 시간으로 대체
	 ***************/

	private String type;
	private String result;
	private String code;
	private String userId;
	private String macAddr;
	private String userIp;
	private String accessTime;
	private String message;
	private String etc;
	private String spName;
	private String browser;

	public String getType()
	{
		return type;
	}

	public void setType(String type)
	{
		this.type = type;
	}

	public String getResult()
	{
		return result;
	}

	public void setResult(String result)
	{
		this.result = result;
	}

	public String getCode()
	{
		return code;
	}

	public void setCode(int code)
	{
		NumberFormat nf = new DecimalFormat("00000000");
		this.code = nf.format(code);
	}

	public String getUserId()
	{
		return userId;
	}

	public void setUserId(String userId)
	{
		this.userId = userId;
	}

	public String getMacAddr()
	{
		return macAddr;
	}

	public void setMacAddr(String macAddr)
	{
		this.macAddr = macAddr;
	}

	public String getUserIp()
	{
		return userIp;
	}

	public void setUserIp(String userIp)
	{
		this.userIp = userIp;
	}

	public String getAccessTime()
	{
		return accessTime;
	}

	public void setAccessTime(String accessTime)
	{
		this.accessTime = accessTime;
	}

	public String getMessage()
	{
		return message;
	}

	public void setMessage(String message)
	{
		this.message = message;
	}

	public String getEtc()
	{
		return etc;
	}

	public void setEtc(String etc)
	{
		this.etc = etc;
	}

	public String getSpName()
	{
		return spName;
	}

	public void setSpName(String spName)
	{
		this.spName = spName;
	}

	public String getBrowser()
	{
		return browser;
	}

	public void setBrowser(String browser)
	{
		this.browser = browser;
	}
}