package com.dreamsecurity.sso.server.api.audit.vo;

public class AupyVO
{
	private String warnCycle;
	private String warnTime;
	private String warnLimit;
	private String verifyCycle;
	private String verifyPoint;
	private String tblSpace;
	private String totalVol;
	private String usedVol;
	private String freeVol;
	private String usedRate;

	public String getWarnCycle()
	{
		return warnCycle;
	}

	public void setWarnCycle(String warnCycle)
	{
		this.warnCycle = warnCycle;
	}

	public String getWarnTime()
	{
		return warnTime;
	}

	public void setWarnTime(String warnTime)
	{
		this.warnTime = warnTime;
	}

	public String getWarnLimit()
	{
		return warnLimit;
	}

	public void setWarnLimit(String warnLimit)
	{
		this.warnLimit = warnLimit;
	}

	public String getVerifyCycle()
	{
		return verifyCycle;
	}

	public void setVerifyCycle(String verifyCycle)
	{
		this.verifyCycle = verifyCycle;
	}

	public String getVerifyPoint()
	{
		return verifyPoint;
	}

	public void setVerifyPoint(String verifyPoint)
	{
		this.verifyPoint = verifyPoint;
	}

	public String getTblSpace()
	{
		return tblSpace;
	}

	public void setTblSpace(String tblSpace)
	{
		this.tblSpace = tblSpace;
	}

	public String getTotalVol()
	{
		return totalVol;
	}

	public void setTotalVol(String totalVol)
	{
		this.totalVol = totalVol;
	}

	public String getUsedVol()
	{
		return usedVol;
	}

	public void setUsedVol(String usedVol)
	{
		this.usedVol = usedVol;
	}

	public String getFreeVol()
	{
		return freeVol;
	}

	public void setFreeVol(String freeVol)
	{
		this.freeVol = freeVol;
	}

	public String getUsedRate()
	{
		return usedRate;
	}

	public void setUsedRate(String usedRate)
	{
		this.usedRate = usedRate;
	}
}