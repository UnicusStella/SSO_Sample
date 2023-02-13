package com.dreamsecurity.sso.agent.log.impl;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

import com.dreamsecurity.sso.agent.log.LogWriter;
import com.dreamsecurity.sso.agent.log.format.FormatFactory;
import com.dreamsecurity.sso.agent.log.format.Formater;
import com.dreamsecurity.sso.agent.log.format.InstanceFormater;
import com.dreamsecurity.sso.agent.log.format.StringFormater;
import com.dreamsecurity.sso.agent.log.format.TypeFormater;

public class FileLogWriter extends LogWriter
{
	private String nameHeader = null;
	private String nameTailer = null;
	private String directory = null;
	private boolean isAutoFlush = false;
	private Formater formaters[] = null;
	private PrintWriter writer = null;
	private String today = null;
	private SimpleDateFormat dateFormatter = null;

	public FileLogWriter()
	{
		nameHeader = null;
		nameTailer = null;
		directory = null;
		isAutoFlush = true;
		formaters = null;
		writer = null;
		today = null;
		dateFormatter = new SimpleDateFormat("yyyyMMdd", Locale.KOREA);
		new SimpleDateFormat("HH:mm:ss", Locale.KOREA);
	}

	protected void initEngine(Map param)
	{
		try
		{
			/***
			directory = (String) param.get("dir");

			if (directory.startsWith("/") == false)
				directory = (String) param.get("home.dir") + File.separator + directory;
			***/
			directory = (String)param.get("home.dir");
			nameHeader = (String) param.get("prefix");
			nameTailer = (String) param.get("suffix");
			isAutoFlush = (new Boolean((String) param.get("autoflush"))).booleanValue();
			String format = (String) param.get("format");
			if (format == null || format.length() < 1)
				dateFormatter = new SimpleDateFormat(format, Locale.KOREA);
			String message = (String) param.get("message");
			if (message != null)
				formaters = makeFormater(message);
			else formaters = makeFormater("[%p][%d{HH:mm:ss}][%t] %m");
		}
		catch (Exception e)
		{
			e.printStackTrace();
			throw new IllegalArgumentException(e.getMessage());
		}
	}

	protected synchronized void writeEngine(int type, String str)
	{
		checkDate();

		StackTraceElement[] traces = (new Exception()).getStackTrace();

		for (int i = 0; i < formaters.length; i++)
		{
			if (formaters[i] instanceof StringFormater)
				writer.write(((StringFormater) formaters[i]).format(str));
			else if (formaters[i] instanceof TypeFormater)
				writer.write(((TypeFormater) formaters[i]).format(type));
			else if (formaters[i] instanceof InstanceFormater)
				writer.write(((InstanceFormater) formaters[i]).format(traces[5]));
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

	private void checkDate()
	{
		String day = dateFormatter.format(new Date());
		if (day.equals(today))
			return;
		try
		{
			if (writer != null)
			{
				try
				{
					writer.close();
				}
				catch (Exception exception)
				{
				}
				writer = null;
			}
			today = day;
			String logname = nameHeader + today + nameTailer;
			writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(new File(directory, logname), true)), isAutoFlush);
		}
		catch (Exception e)
		{
			writer = new PrintWriter(new BufferedWriter(new OutputStreamWriter(System.out)), true);
			writer.println("[LoggerWriter]로그 파일을 열 수 없습니다.(원인: " + e.getMessage() + ")");
			writer.println("[LoggerWriter]로그가 콘솔로 출력됩니다.");
		}
	}

	public Formater[] makeFormater(String msg)
	{
		ArrayList order = new ArrayList();
		FormatFactory ff = new FormatFactory();
		boolean isWraped = false;
		boolean isFormat = false;
		StringBuffer buffer = new StringBuffer();
		char cmd = '\0';
		for (int i = 0; i < msg.length(); i++)
		{
			if (isWraped)
			{
				if (msg.charAt(i) == '\'')
				{
					isWraped = false;
					if (buffer.length() > 0)
						order.add(ff.getStringFormater(buffer.toString()));
					buffer = new StringBuffer();
				}
				else
				{
					buffer.append(msg.charAt(i));
				}
			}
			else if (msg.charAt(i) == '\'')
			{
				if (buffer.length() > 0)
					order.add(ff.getStringFormater(buffer.toString()));
				buffer = new StringBuffer();
				isWraped = true;
			}
			else if (isFormat)
			{
				if (msg.charAt(i) == '}')
				{
					isFormat = false;
					order.add(ff.getFormater(cmd, buffer.toString()));
					buffer = new StringBuffer();
				}
				else
				{
					buffer.append(msg.charAt(i));
				}
			}
			else if (msg.charAt(i) == '%')
			{
				if (i + 1 == msg.length())
					throw new IllegalArgumentException("Invalid Message Format String [" + msg + "]");
				if (buffer.length() > 0)
					order.add(ff.getStringFormater(buffer.toString()));
				buffer = new StringBuffer();
				cmd = msg.charAt(++i);
				if (i + 1 < msg.length() && msg.charAt(i + 1) == '{')
				{
					i++;
					isFormat = true;
				}
				else
				{
					order.add(ff.getFormater(cmd, null));
				}
			}
			else
			{
				buffer.append(msg.charAt(i));
			}
		}

		if (buffer.length() > 0)
			order.add(ff.getStringFormater(buffer.toString()));
		Formater result[] = new Formater[order.size()];
		order.toArray(result);
		return result;
	}
}