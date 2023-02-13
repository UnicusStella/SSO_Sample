package com.dreamsecurity.sso.agent.log.format;

import java.util.Map;

import com.dreamsecurity.sso.agent.log.format.ClassNameFormat;
import com.dreamsecurity.sso.agent.log.format.Formater;
import com.dreamsecurity.sso.agent.log.format.LineNumberFormat;
import com.dreamsecurity.sso.agent.log.format.MessageFormat;
import com.dreamsecurity.sso.agent.log.format.MethodNameFormat;
import com.dreamsecurity.sso.agent.log.format.PriorityFormat;
import com.dreamsecurity.sso.agent.log.format.SimpleFormat;
import com.dreamsecurity.sso.agent.log.format.SourceNameFormat;
import com.dreamsecurity.sso.agent.log.format.ThreadFormat;
import com.dreamsecurity.sso.agent.log.format.TimeFormat;

public class FormatFactory
{

	int priority = 0;

	public void initParameter(Map map1)
	{
	}

	public Formater getStringFormater(String msg)
	{
		return getFormater('s', msg);
	}

	public Formater getFormater(char cmd, String format)
	{
		switch(cmd)
		{
		case 116: // 't'
			return new ThreadFormat();

		case 100: // 'd'
			return new TimeFormat(format);

		case 112: // 'p'
			return new PriorityFormat(false);

		case 80: // 'P'
			return new PriorityFormat(true);

		case 110: // 'n'
			return new SimpleFormat("\r\n");

		case 109: // 'm'
			return new MessageFormat();

		case 115: // 's'
			return new SimpleFormat(format);
			
		case 'M':
			return new MethodNameFormat();
			
		case 'C':
			return new ClassNameFormat(false);
			
		case 'c':
			return new ClassNameFormat(true);
			
		case 'L':
			return new LineNumberFormat();
			
		case 'F':
			return new SourceNameFormat();
			
		
		}
		return null;
	}

	public FormatFactory()
	{

	}
}