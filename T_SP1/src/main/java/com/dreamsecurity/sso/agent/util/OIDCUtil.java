package com.dreamsecurity.sso.agent.util;

import java.security.SecureRandom;
import java.util.Random;
import java.util.UUID;

public class OIDCUtil
{
	public static final int DEFAULT_LENGTH = 128;
	public static final char[] UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
	public static final char[] DIGITS = "0123456789".toCharArray();
	public static final char[] ALPHANUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();

	private static ThreadLocal<Random> random = new ThreadLocal<Random>() {
		@Override
		protected Random initialValue()
		{
			return new SecureRandom();
		}
	};

	public static String generateUUID()
	{
		UUID uudi = UUID.randomUUID();
		return uudi.toString();
	}

	public static String randomString()
	{
		return randomString(DEFAULT_LENGTH, ALPHANUM);
	}

	public static String randomString(int length)
	{
		return randomString(length, ALPHANUM);
	}

	public static String randomString(int length, char[] symbols)
	{
		if (length < 1) {
			throw new IllegalArgumentException();
		}

		if (symbols == null || symbols.length < 2) {
			throw new IllegalArgumentException();
		}

		Random r = random.get();
		char[] buf = new char[length];

		for (int idx = 0; idx < buf.length; ++idx) {
			buf[idx] = symbols[r.nextInt(symbols.length)];
		}

		return new String(buf);
	}

	public static String base64ToBase64url(String input)
	{
		String output = input.replace("+", "-").replace("/", "_").replace("=", "");
		return output;
	}

	public static String base64urlToBase64(String input)
	{
		String output = input.replace("-", "+").replace("_", "/");
		int i = 0;
		int count = output.length() % 4;

		if (count != 0) {
			for (i = 4; i > count; i--) {
				output = output + "=";
			}
		}

		return output;
	}
}