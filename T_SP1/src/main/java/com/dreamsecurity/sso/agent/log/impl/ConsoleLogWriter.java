package com.dreamsecurity.sso.agent.log.impl;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Map;

import com.dreamsecurity.sso.agent.log.LogWriter;
import com.dreamsecurity.sso.agent.log.format.FormatFactory;
import com.dreamsecurity.sso.agent.log.format.Formater;
import com.dreamsecurity.sso.agent.log.format.InstanceFormater;
import com.dreamsecurity.sso.agent.log.format.StringFormater;
import com.dreamsecurity.sso.agent.log.format.TypeFormater;

public class ConsoleLogWriter extends LogWriter
{
	private boolean isAutoFlush = false;
	private Formater formaters[] = null;
	private PrintWriter writer = null;


	public ConsoleLogWriter()
	{
		isAutoFlush = true;
		formaters = null;
		writer = null;

	}

	protected void initEngine(Map param)
	{
		try
		{
			isAutoFlush = (new Boolean((String)param.get("autoflush"))).booleanValue();

			String message = (String)param.get("message");
			if(message != null)
				formaters = makeFormater(message);
			else
				formaters = makeFormater("[%p][%d{HH:mm:ss}][%t] %m");
			
			
			writer = new PrintWriter(System.out,this.isAutoFlush);
		}
		catch(Exception e)
		{
			e.printStackTrace();
			throw new IllegalArgumentException(e.getMessage());
		}
	}

	protected synchronized void writeEngine(int type,String str)
	{
		
    	StackTraceElement[] traces = (new Exception()).getStackTrace();

		for(int i = 0; i < formaters.length; i++)
		{
			if (formaters[i] instanceof StringFormater)
				writer.write(((StringFormater)formaters[i]).format(str));
			else if (formaters[i] instanceof TypeFormater)
				writer.write(((TypeFormater)formaters[i]).format(type));
			else if (formaters[i] instanceof InstanceFormater)
				writer.write(((InstanceFormater)formaters[i]).format(traces[5]));			
		}
		
		writer.flush();
	}

	protected void flushEngine()
	{
		writer.flush();
	}

	protected void closeEngine()
	{
		writer.close();
	}

	public Formater[] makeFormater(String msg)
	{
		ArrayList order = new ArrayList();
		FormatFactory ff = new FormatFactory();
		boolean isWraped = false;
		boolean isFormat = false;
		StringBuffer buffer = new StringBuffer();
		char cmd = '\0';
		for(int i = 0; i < msg.length(); i++)
		{
			if(isWraped)
			{
				if(msg.charAt(i) == '\'')
				{
					isWraped = false;
					if(buffer.length() > 0)
						order.add(ff.getStringFormater(buffer.toString()));
					buffer = new StringBuffer();
				} else
				{
					buffer.append(msg.charAt(i));
				}
			} else
			if(msg.charAt(i) == '\'')
			{
				if(buffer.length() > 0)
					order.add(ff.getStringFormater(buffer.toString()));
				buffer = new StringBuffer();
				isWraped = true;
			} else
			if(isFormat)
			{
				if(msg.charAt(i) == '}')
				{
					isFormat = false;
					order.add(ff.getFormater(cmd, buffer.toString()));
					buffer = new StringBuffer();
				} else
				{
					buffer.append(msg.charAt(i));
				}
			} else
			if(msg.charAt(i) == '%')
			{
				if(i + 1 == msg.length())
					throw new IllegalArgumentException("Invalid Message Format String [" + msg + "]");
				if(buffer.length() > 0)
					order.add(ff.getStringFormater(buffer.toString()));
				buffer = new StringBuffer();
				cmd = msg.charAt(++i);
				if(i + 1 < msg.length() && msg.charAt(i + 1) == '{')
				{
					i++;
					isFormat = true;
				} else
				{
					order.add(ff.getFormater(cmd, null));
				}
			} else
			{
				buffer.append(msg.charAt(i));
			}
		}

		if(buffer.length() > 0)
			order.add(ff.getStringFormater(buffer.toString()));
		Formater result[] = new Formater[order.size()];
		order.toArray(result);
		return result;
	}
}