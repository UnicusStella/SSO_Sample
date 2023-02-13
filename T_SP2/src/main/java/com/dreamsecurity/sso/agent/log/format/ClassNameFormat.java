package com.dreamsecurity.sso.agent.log.format;

import com.dreamsecurity.sso.agent.log.format.InstanceFormater;

public class ClassNameFormat implements InstanceFormater
{
	public String format(StackTraceElement trace)
	{
		return isShort ? getShortName(trace.getClassName()) : trace.getClassName();
	}

	private String getShortName(String name)
	{
		return name.substring(name.lastIndexOf(".") + 1);
	}

	boolean isShort = true;

	public ClassNameFormat(boolean isShort)
	{
		this.isShort = isShort;
	}
}