package com.dreamsecurity.sso.server.api.admin.vo;

public class AdpyVO
{
	private String pwMismatchAllow;
	private String lockTime;
	private String sessionTime;
	private String ipMaxCount;

	public String getPwMismatchAllow()
	{
		return pwMismatchAllow;
	}

	public void setPwMismatchAllow(String pwMismatchAllow)
	{
		this.pwMismatchAllow = pwMismatchAllow;
	}

	public String getLockTime()
	{
		return lockTime;
	}

	public void setLockTime(String lockTime)
	{
		this.lockTime = lockTime;
	}

	public String getSessionTime()
	{
		return sessionTime;
	}

	public void setSessionTime(String sessionTime)
	{
		this.sessionTime = sessionTime;
	}

	public String getIpMaxCount()
	{
		return ipMaxCount;
	}

	public void setIpMaxCount(String ipMaxCount)
	{
		this.ipMaxCount = ipMaxCount;
	}
}