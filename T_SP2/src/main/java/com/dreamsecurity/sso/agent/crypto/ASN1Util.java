package com.dreamsecurity.sso.agent.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.StringTokenizer;
import java.util.TimeZone;

public class ASN1Util
{
	public static int SEQUENCE = 0x30;
	public static int SET = 0x31;
	public static int BOOLEAN = 0x01;
	public static int INTEGER = 0x02;
	public static int BITSTRING = 0x03;
	public static int OCTETSTRING = 0x04;
	public static int NULL = 0x05;
	public static int OID = 0x06;
	public static int ENUMERATED = 0x0A;
	public static int UTF8STRING = 0x0C;
	public static int PRINTABLESTRING = 0x13;
	public static int UTCTIME = 0x17;
	public static int GENERALIZEDTIME = 0x18;

	public static String id_md5 = "1.2.840.113549.2.5";
	public static String id_sha1 = "1.3.14.3.2.26";
	public static String id_sha256 = "2.16.840.1.101.3.4.2.1";
	public static String id_sha512 = "2.16.840.1.101.3.4.2.3";
	public static String id_has160 = "1.2.410.200004.1.2";
	public static String id_kcdsa1 = "1.2.410.200004.1.21";
	public static String id_rsaEncryption = "1.2.840.113549.1.1.1";
	public static String id_RSAES_OAEP = "1.2.840.113549.1.1.7";
	public static String id_RSASSA_PSS = "1.2.840.113549.1.1.10";
	public static String id_ea_rsa = "2.5.8.1.1";

	private static int _unusedBit = 0;

	public static byte[] getASN1(byte[] encoded, int type) throws IOException
	{
		int len = 0, i, lengthLen;
		int pos = 0;
		byte[] value = null;

		if (encoded[pos++] != type)
			throw new IOException("invalid encoded value.");

		if ((encoded[pos] & 0x80) == 0)
			len = (encoded[pos++] & 0x000000ff);
		else {
			lengthLen = encoded[pos++] & 0x0f;
			for (i = 0; i < lengthLen; i++) {
				len <<= 8;
				len |= (encoded[pos++] & 0x000000ff);
			}
		}

		if (type == BITSTRING) {
			pos++;
			len--;
		}

		value = new byte[len];
		System.arraycopy(encoded, pos, value, 0, len);
		return value;
	}

	public static boolean getBoolean(byte[] encoded) throws IOException
	{
		byte[] value = getASN1(encoded, BOOLEAN);
		if (value[0] != 0)
			return true;
		return false;
	}

	public static BigInteger getInteger(byte[] encoded) throws IOException
	{
		return new BigInteger(1, getASN1(encoded, INTEGER));
	}

	public static byte[] getBitString(byte[] encoded) throws IOException
	{
		return getASN1(encoded, BITSTRING);
	}

	public static byte[] getOctetString(byte[] encoded) throws IOException
	{
		return getASN1(encoded, OCTETSTRING);
	}

	public static String getObjectIdentifier(byte[] encoded) throws IOException
	{
		byte[] oid = getASN1(encoded, OID);
		StringBuffer sb = new StringBuffer();

		sb.append(oid[0] / 40);
		sb.append(".");
		sb.append(oid[0] % 40);

		for (int i = 1; i < oid.length;) {
			sb.append(".");
			int t = 0;

			do {
				t <<= 7;
				t |= oid[i] & 0x7f;
			} while ((oid[i++] & 0x80) != 0);

			sb.append(t);
		}

		return sb.toString();
	}

	public static int getEnumerated(byte[] encoded) throws IOException
	{
		byte[] value = getASN1(encoded, ENUMERATED);
		return (int) value[0];
	}

	public static String getUTF8String(byte[] encoded) throws IOException
	{
		byte[] value = getASN1(encoded, UTF8STRING);
		return new String(value, "UTF-8");
	}

	public static String getPrintableString(byte[] encoded) throws IOException
	{
		byte[] value = getASN1(encoded, PRINTABLESTRING);
		return new String(value);
	}

	/**
	 * JRE1.4 ������ �׻� GMT�θ� �����Ǵ� ������ �ִ�.
	 */
	public static Date getUtcTime(byte[] encoded) throws IOException
	{
		byte[] value = getASN1(encoded, UTCTIME);
		String string = new String(value, 0, value.length - 1);
		SimpleDateFormat fmt = new SimpleDateFormat("yyMMddHHmmss");
		fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
		// jre 1.5 �������� ������... 1.4������ gmt �� ��������. 1.5������ kst�� ����.. �׷��� �ð���..
		try {
			return fmt.parse(string);
		} catch (ParseException e) {
			try {
				fmt = new SimpleDateFormat("yyMMddHHmmss.SSS");
				return fmt.parse(string);
			} catch (ParseException pe) {
				throw new IOException(pe.getMessage());
			}
		}
	}

	/**
	 * JRE1.4 ������ �׻� GMT�θ� �����Ǵ� ������ �ִ�.
	 */
	public static Date getGeneralizedTime(byte[] encoded) throws IOException
	{
		byte[] value = getASN1(encoded, GENERALIZEDTIME);
		String string = new String(value, 0, value.length - 1);
		string.replaceAll(",", ".");
		SimpleDateFormat fmt = new SimpleDateFormat("yyyyMMddHHmmss.SSS");
		fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
		try {
			return fmt.parse(string);
		} catch (ParseException e) {
			try {
				fmt = new SimpleDateFormat("yyyyMMddHHmmss");
				return fmt.parse(string);
			} catch (ParseException pe) {
				throw new IOException(pe.getMessage());
			}
		}
	}

	public static byte[][] getSequence(byte[] encoded) throws IOException
	{
		int len = 0, i, lengthLen = 1;
		int pos = 0, nodeCount = 0;
		byte[] value = null;
		byte[][] node = null;

		byte s = encoded[pos++];
		if (s != SEQUENCE && s != SET)
			throw new IOException("invalid encoded value.");

		if ((encoded[pos] & 0x80) == 0)
			len = (encoded[pos++] & 0x000000ff);
		else {
			lengthLen = encoded[pos++] & 0x0f;
			for (i = 0; i < lengthLen; i++) {
				len <<= 8;
				len |= (encoded[pos++] & 0x000000ff);
			}
		}

		try {

			do {
				pos++;
				if ((encoded[pos] & 0x80) == 0)
					len = (encoded[pos++] & 0x000000ff);
				else {
					len = 0;
					lengthLen = encoded[pos++] & 0x0f;
					for (i = 0; i < lengthLen; i++) {
						len <<= 8;
						len |= (encoded[pos++] & 0x000000ff);
					}
				}
				pos += len;
				nodeCount++;

			} while (pos < encoded.length);

			node = new byte[nodeCount][];

			for (i = 0; i < nodeCount; i++) {
				value = getNode(encoded, i);
				node[i] = new byte[value.length];
				System.arraycopy(value, 0, node[i], 0, value.length);
			}

		} catch (Exception e) {
			throw new IOException("invalid node " + node + ".");
		}

		return node;
	}

	public static byte[][] getSet(byte[] encoded) throws IOException
	{
		return getSequence(encoded);
	}

	// ��尹���� �̸� �Ҵ��س��� ���������� ���������鼭 ������� �˻�
	public static byte[][] getSequence2(byte[] encoded) throws IOException
	{
		int len = 0, i, lengthLen = 1;
		int pos = 0, nodePos = 0, nodeCount = 0;
		int maxNode = 10;
		byte[][] nodeTemp = new byte[maxNode][];

		byte s = encoded[pos++];
		if (s != SEQUENCE && s != SET)
			throw new IOException("invalid encoded value.");

		if ((encoded[pos] & 0x80) == 0)
			len = (encoded[pos++] & 0x000000ff);
		else {
			lengthLen = encoded[pos++] & 0x0f;
			for (i = 0; i < lengthLen; i++) {
				len <<= 8;
				len |= (encoded[pos++] & 0x000000ff);
			}
		}

		try {

			do {
				nodePos = pos;
				pos++;
				if ((encoded[pos] & 0x80) == 0)
					len = (encoded[pos++] & 0x000000ff);
				else {
					lengthLen = encoded[pos++] & 0x0f;
					for (i = 0; i < lengthLen; i++) {
						len <<= 8;
						len |= (encoded[pos++] & 0x000000ff);
					}
				}
				pos += len;
				nodeTemp[nodeCount] = new byte[1 + lengthLen + len];

				System.arraycopy(encoded, nodePos, nodeTemp[nodeCount], 0, 1 + lengthLen + len);
				nodeCount++;
				if (nodeCount > maxNode) {
					maxNode *= 2;
					byte[][] nodeMoreTemp = new byte[maxNode][];
					for (i = 0; i < nodeTemp.length; i++)
						nodeMoreTemp[i] = nodeTemp[i];
					nodeTemp = nodeMoreTemp;
				}

			} while (pos < encoded.length);

		} catch (Exception e) {
			throw new IOException("invalid encoded value.");
		}

		byte[][] node = new byte[nodeCount][];

		for (i = 0; i < nodeCount; i++) {
			node[i] = nodeTemp[i];
		}

		return node;
	}

	public static byte[] getNode(byte[] encoded, int node) throws IOException
	{
		int len = 0, i, j, lengthLen = 1;
		int pos = 0, nodePos = 0;
		byte[] value = null;

		byte s = encoded[pos++];
		if (s != SEQUENCE && s != SET)
			throw new IOException("invalid encoded value.");

		if ((encoded[pos] & 0x80) == 0)
			len = (encoded[pos++] & 0x000000ff);
		else {
			lengthLen += encoded[pos++] & 0x0f;
			for (i = 0; i < lengthLen - 1; i++) {
				len <<= 8;
				len |= (encoded[pos++] & 0x000000ff);
			}
		}

		try {

			// skip
			for (i = 0; i < node; i++) {
				pos++;

				len = 0;
				lengthLen = 1;
				if ((encoded[pos] & 0x80) == 0)
					len = (encoded[pos++] & 0x000000ff);
				else {
					lengthLen += encoded[pos++] & 0x0f;

					for (j = 0; j < lengthLen - 1; j++) {
						len <<= 8;
						len |= (encoded[pos++] & 0x000000ff);
					}
				}
				pos += len;
			}

			nodePos = pos;
			pos++;
			len = 0;
			lengthLen = 1;
			if ((encoded[pos] & 0x80) == 0)
				len = (encoded[pos++] & 0x000000ff);
			else {
				lengthLen += encoded[pos++] & 0x0f;
				len = 0;
				for (i = 0; i < lengthLen - 1; i++) {
					len <<= 8;
					len |= (encoded[pos++] & 0x000000ff);
				}
			}

			value = new byte[1 + lengthLen + len];
			System.arraycopy(encoded, nodePos, value, 0, 1 + lengthLen + len);

		} catch (Exception e) {
			throw new IOException("invalid node " + node + ".");
		}

		return value;
	}

	public static byte[] setASN1(byte[] value, int type) throws IOException
	{
		int len = 0, i, length = value.length;
		ByteArrayOutputStream encoded = new ByteArrayOutputStream();

		encoded.reset();
		encoded.write(type);

		if (type == INTEGER) {
			if ((value[0] & 0x80) != 0)
				length++;
		} else if (type == BITSTRING)
			length++;
		else if (type == NULL) {
			encoded.write(0x00);
			return encoded.toByteArray();
		}

		if (length < 0x80)
			encoded.write(length);
		else {
			len = (length & 0xffff0000) != 0 ? ((length & 0xff000000) != 0 ? 4 : 3) : ((length & 0x0000ff00) != 0 ? 2 : 1);
			encoded.write(0x80 | len);
			for (i = len - 1; i >= 0; i--) {
				encoded.write((length >> (i * 8)) & 0xff);
			}
		}

		if (type == INTEGER) {
			if ((value[0] & 0x80) != 0)
				encoded.write(0x00);
		} else if (type == BITSTRING)
			encoded.write(_unusedBit);

		encoded.write(value);
		return encoded.toByteArray();
	}

	public static byte[] setInteger(int value) throws IOException
	{
		int i;
		int len = (value & 0xffff0000) != 0 ? ((value & 0xff000000) != 0 ? 4 : 3) : ((value & 0x0000ff00) != 0 ? 2 : 1);

		byte[] tmp = new byte[len];
		for (i = len - 1; i >= 0; i--)
			tmp[i] = (byte) ((value >> (i * 8)) & 0xff);

		return setASN1(tmp, INTEGER);
	}

	public static byte[] setBoolean(boolean value) throws IOException
	{
		byte[] bool = new byte[1];
		if (value)
			bool[0] = (byte) 0xff;
		else
			bool[0] = 0;
		return setASN1(bool, BOOLEAN);
	}

	public static byte[] setInteger(BigInteger value) throws IOException
	{
		return setASN1(value.toByteArray(), INTEGER);
	}

	public static byte[] setBitString(byte[] value) throws IOException
	{
		_unusedBit = 0;
		return setASN1(value, BITSTRING);
	}

	public static byte[] setBitString(byte[] value, int unusedBit) throws IOException
	{
		_unusedBit = unusedBit;
		return setASN1(value, BITSTRING);
	}

	public static byte[] setBitString(byte[] value, boolean unusedBit) throws IOException
	{
		int flag = 1;
		_unusedBit = 0;

		if (unusedBit) {
			while ((value[value.length - 1] & flag) == 0) {
				flag <<= 1;
				_unusedBit++;
			}
		}
		return setASN1(value, BITSTRING);
	}

	public static byte[] setOctetString(byte[] value) throws IOException
	{
		return setASN1(value, OCTETSTRING);
	}

	public static byte[] setNull() throws IOException
	{
		byte[] tmp = new byte[1];
		return setASN1(tmp, NULL);
	}

	public static byte[] setObjectIdentifier(String value) throws IOException
	{
		StringTokenizer st = new StringTokenizer(value, ".");
		int count = st.countTokens();
		String token = null;
		int i, j, t, len;

		if (count < 2)
			throw new IOException("invalid OID value.");

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		int first = Integer.parseInt(st.nextToken());
		first = first * 40 + Integer.parseInt(st.nextToken());
		baos.write((byte) first);

		for (i = 2; i < count; i++) {
			token = st.nextToken();
			t = Integer.parseInt(token);

			len = ((t & 0x0fffc000) != 0) ? (((t & 0x0fe00000) != 0) ? 4 : 3) : (((t & 0x00003f80) != 0) ? 2 : 1);

			for (j = len - 1; j > 0; j--) {
				byte a = (byte) ((t >> j * 7) & 0x7f);
				baos.write((byte) (0x80 | a));
			}
			baos.write(t & 0x7f);
		}

		return setASN1(baos.toByteArray(), OID);
	}

	public static byte[] setEnumerated(int value) throws IOException
	{
		byte[] binEnum = new byte[1];
		binEnum[0] = (byte) value;
		return setASN1(binEnum, ENUMERATED);
	}

	public static byte[] setUTF8String(String value) throws IOException
	{
		byte[] utf8 = value.getBytes("UTF-8");
		return setASN1(utf8, UTF8STRING);
	}

	public static byte[] setPrintableString(String value) throws IOException
	{
		byte[] string = value.getBytes();
		return setASN1(string, PRINTABLESTRING);
	}

	public static byte[] setUtcTime(String value) throws IOException
	{
		return setASN1(value.getBytes(), UTCTIME);
	}

	public static byte[] setUtcTime(Date value) throws IOException
	{
		SimpleDateFormat fmt = new SimpleDateFormat("yyMMddHHmmss");
		fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
		String string = fmt.format(value) + "Z";
		return setASN1(string.getBytes(), UTCTIME);
	}

	public static byte[] setGeneralizedTime(String value) throws IOException
	{
		SimpleDateFormat fmt = new SimpleDateFormat("yyMMddHHmmss.SSS");
		fmt.setTimeZone(TimeZone.getTimeZone("UTC"));
		String string = fmt.format(value) + "Z";
		return setASN1(string.getBytes(), GENERALIZEDTIME);
	}

	public static byte[] setGeneralizedTime(Date value) throws IOException
	{
		SimpleDateFormat fmt = new SimpleDateFormat("yyyyMMddHHmmss.SSS");
		String string = fmt.format(value) + "Z";
		return setASN1(string.getBytes(), GENERALIZEDTIME);
	}

	public static byte[] setSequence(byte[] value) throws IOException
	{
		return setASN1(value, SEQUENCE);
	}

	public static byte[] setSet(byte[] value) throws IOException
	{
		return setASN1(value, SET);
	}

	public static byte[] setAlgorithmIdentifier(String oid, byte[] param) throws IOException
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		baos.write(setObjectIdentifier(oid));
		baos.write(param);

		return setSequence(baos.toByteArray());
	}
}
