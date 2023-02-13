package com.dreamsecurity.sso.server.api.admin.vo;

public class UrpyVO
{
	private String pwMismatchAllow;
	private String pwChangeWarn;
	private String pwValidate;
	private String dupCheckType;
	private String pollingTime;
	private String sessionTime;

	public String getPwMismatchAllow()
	{
		return pwMismatchAllow;
	}

	public void setPwMismatchAllow(String pwMismatchAllow)
	{
		this.pwMismatchAllow = pwMismatchAllow;
	}

	public String getPwChangeWarn()
	{
		return pwChangeWarn;
	}

	public void setPwChangeWarn(String pwChangeWarn)
	{
		this.pwChangeWarn = pwChangeWarn;
	}

	public String getPwValidate()
	{
		return pwValidate;
	}

	public void setPwValidate(String pwValidate)
	{
		this.pwValidate = pwValidate;
	}

	public String getDupCheckType()
	{
		return dupCheckType;
	}

	public void setDupCheckType(String dupCheckType)
	{
		this.dupCheckType = dupCheckType;
	}

	public String getPollingTime()
	{
		return pollingTime;
	}

	public void setPollingTime(String pollingTime)
	{
		this.pollingTime = pollingTime;
	}

	public String getSessionTime()
	{
		return sessionTime;
	}

	public void setSessionTime(String sessionTime)
	{
		this.sessionTime = sessionTime;
	}
}