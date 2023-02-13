package com.dreamsecurity.sso.agent.http11;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Http11NioProtocol extends org.apache.coyote.http11.Http11NioProtocol
{
	@Override
	public void setKeystorePass(String str)
	{
		try {
			String OS = System.getProperty("os.name").toLowerCase();

			if (OS.indexOf("win") >= 0) {
				super.setKeystorePass(str);
			}
			else {
				StringBuffer sb = new StringBuffer();
				sb.append("echo '").append(str).append("' | openssl enc -aes-256-cbc -a -pass pass:'Dre@mM@gicSS0' -d");

				Process ps = new ProcessBuilder("/bin/sh", "-c", sb.toString()).start();

				BufferedReader stdOut = new BufferedReader(new InputStreamReader(ps.getInputStream()));
				String readline = stdOut.readLine();
				//System.out.println("### SSL keystorePass = [" + readline + "]");

				super.setKeystorePass(readline);
			}
		}
		catch (final Exception e) {
			super.setKeystorePass("");
		}
	}
}