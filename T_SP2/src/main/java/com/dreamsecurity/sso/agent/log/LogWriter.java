// Decompiled by DJ v3.5.5.77 Copyright 2003 Atanas Neshkov  Date: 2007-10-08 오후 4:04:26
// Home Page : http://members.fortunecity.com/neshkov/dj.html  - Check often for new version!
// Decompiler options: packimports(3) definits fieldsfirst ansi 
// Source File Name:   LoggerWriter.java

package com.dreamsecurity.sso.agent.log;

import java.util.Map;

public abstract class LogWriter
{

	protected String lineSeparator = null;

	public LogWriter()
	{
		lineSeparator = System.getProperty("line.separator");
	}

	public void initLogger(Map<String, String> param)
	{
		initEngine(param);
	}

	public void finalize()
	{
		flushEngine();
		closeEngine();
	}

	public void close()
	{
		closeEngine();
	}

	public void flush()
	{
		flushEngine();
	}

	public void write(int type, String message)
	{
		writeEngine(type,message);
	}


	protected abstract void initEngine(Map<String, String> map);

	protected abstract void writeEngine(int type,String message);

	protected abstract void flushEngine();

	protected abstract void closeEngine();
}