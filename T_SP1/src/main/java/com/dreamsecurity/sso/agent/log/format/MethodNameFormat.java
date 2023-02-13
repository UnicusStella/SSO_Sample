package com.dreamsecurity.sso.agent.log.format;

import com.dreamsecurity.sso.agent.log.format.InstanceFormater;

public class MethodNameFormat implements InstanceFormater
{

	public String format(StackTraceElement trace)
	{
		return trace.getMethodName();
	}
}
