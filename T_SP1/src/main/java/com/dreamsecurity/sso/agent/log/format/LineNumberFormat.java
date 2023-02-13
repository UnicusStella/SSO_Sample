package com.dreamsecurity.sso.agent.log.format;

import com.dreamsecurity.sso.agent.log.format.InstanceFormater;

public class LineNumberFormat implements InstanceFormater
{
	public String format(StackTraceElement trace)
	{
		return Integer.toString(trace.getLineNumber());
	}
}
