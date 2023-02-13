package com.dreamsecurity.sso.agent.util;

import java.util.Random;

public class ByteUtil
{
	public static long toLong(byte[] src, int srcOff)
	{
		long tot = 0;
		for (int i = srcOff; i < src.length; i++) {
			tot <<= 8;
			// tot += Integer.valueOf(i);
			// support 1.4 mod
			tot += (new Integer(src[i]).intValue());
		}
		return tot;
	}

	public static void longToBytes(byte[] dest, int destOff, long value)
	{
		for (int i = 0; i < 8; i++) {
			dest[i + destOff] = (byte) (value >> ((7 - i) * 8));
		}
	}

	public static int toInt(byte[] bytes)
	{
		return toInt(bytes, 0);
	}

	public static int toInt(byte[] src, int srcOff)
	{
		int tot = 0;
		for (int i = srcOff; i < src.length; i++) {
			tot <<= 8;
			// tot += Integer.valueOf(i);
			// support 1.4 mod
			tot += (new Integer(src[i]).intValue());
		}
		return tot;
	}

	public static int bytesToInt(byte[] src, int srcOff)
	{
		int word = 0;

		for (int i = 0; i <= 3; i++) {
			word = (word << 4) + (src[i + srcOff] & 0xff);
		}

		return word;
	}

	public static void intToBytes(byte[] dest, int destOff, int value)
	{
		for (int i = 0; i < 4; i++) {
			dest[i + destOff] = (byte) (value >> ((3 - i) * 8));
		}
	}

	public static boolean compareBytes(byte[] source, byte[] dest)
	{
		if (source.length != dest.length)
			return false;

		for (int i = 0; i < source.length; i++) {
			if (source[i] != dest[i])
				return false;
		}
		return true;
	}

	public static byte[] concatBytes(byte[] firstBytes, byte[] nextBytes)
	{
		byte[] bytes = new byte[firstBytes.length + nextBytes.length];

		System.arraycopy(nextBytes, 0, bytes, 0, nextBytes.length);
		System.arraycopy(firstBytes, 0, bytes, nextBytes.length, firstBytes.length);
		return bytes;
	}

	public static void splitBytes(byte[] source, byte[] firstBytes, byte[] nextBytes)
	{
		System.arraycopy(source, 0, firstBytes, 0, firstBytes.length);
		System.arraycopy(source, firstBytes.length, nextBytes, 0, nextBytes.length);
	}

	public static String toHexString(byte[] bytes)
	{
		StringBuffer sb = new StringBuffer(40);
		String hexstr;

		for (int i = 0; i < bytes.length; i++) {
			hexstr = Integer.toHexString(bytes[i]);
			if (hexstr.length() < 2)
				hexstr = "0" + hexstr;
			sb.append(hexstr.substring(hexstr.length() - 2));
		}

		return sb.toString();
	}

	public static byte[] toBytes(String bytestr)
	{
		byte[] bytes = new byte[bytestr.length() / 2];
		String hexstr;

		for (int i = 0; i < bytes.length; i++) {
			hexstr = bytestr.substring(i * 2, (i + 1) * 2);
			bytes[i] = (byte) Integer.parseInt(hexstr, 16);
		}

		return bytes;
	}

	public static byte[] getRandomNumber(int size)
	{
		byte[] byteRand = new byte[size];
		(new Random()).nextBytes(byteRand);
		return byteRand;
	}

	public static boolean equals(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2)
	{
		if (paramArrayOfByte1 == paramArrayOfByte2)
			return true;
		if (paramArrayOfByte1.length != paramArrayOfByte2.length)
			return false;
		return equals(paramArrayOfByte1, 0, paramArrayOfByte2, 0, paramArrayOfByte1.length);
	}

	public static boolean a;

	public static boolean equals(byte[] paramArrayOfByte1, int paramInt1, byte[] paramArrayOfByte2, int paramInt2, int paramInt3)
	{
		boolean bool = a;
		int i = 0;
		do {
			if (i >= paramInt3)
				break;
			if (paramArrayOfByte1[(paramInt1 + i)] != paramArrayOfByte2[(paramInt2 + i)])
				return false;
			++i;
		}
		while (!(bool));
		return true;
	}
}
