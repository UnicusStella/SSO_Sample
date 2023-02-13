package com.dreamsecurity.sso.agent.config;

import java.security.MessageDigest;

import com.dreamsecurity.jcaos.jce.provider.JCAOSProvider;
import com.dreamsecurity.jcaos.util.FileUtil;
import com.dreamsecurity.sso.lib.xsc.utils.Base64;

public class InitStart
{
	final static String providerName = "JCAOS" ;

	static {
		JCAOSProvider.installProvider();
	}

	private static void outPrint(String format)
	{
		System.out.printf(format);
	}

	public static void main(String[] args)
	{
		try {
			byte[] cert = FileUtil.read(args[1]);
			byte[] data = new byte[args[0].getBytes().length + cert.length];
			System.arraycopy(args[0].getBytes(), 0, data, 0, args[0].getBytes().length);
			System.arraycopy(cert, 0, data, args[0].getBytes().length, cert.length);

			MessageDigest md = MessageDigest.getInstance("SHA256", providerName);
			byte[] byteData = md.digest(data);
			outPrint(Base64.encode(byteData));
		}
		catch (Exception e) {
			outPrint("\nSSO Crypto Exception : " + e.getMessage() + "\n\n");
		}
	}
}