/*******************************************************************************

  Product:       Kryptel/Java
  File:          Conversions.java
  Description:   https://www.kryptel.com/articles/developers/java/bslx.conversions.php

  Copyright (c) 2017 Inv Softworks LLC,    http://www.kryptel.com

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*******************************************************************************/


package com.kryptel.bslx;


import java.util.UUID;


//
// Note that all offset arguments are bytes. For example, if copying is to start
// from the fourth element of an int array, specify offset 12 (3 * sizeof(int))
//

public final class Conversions {
	public static void ToBytes(byte[] dest, int to, short[] src, int from, int len) {
		int bfrom = from / 2;
		int shift = 8 * (from % 2);
		
		for (;;) {
			dest[to++] = (byte)(src[bfrom] >>> shift);
			if (--len == 0) break;
			shift += 8;
			if (shift == 16) {
				shift = 0;
				bfrom++;
			}
		}
	}

	public static void ToBytes(byte[] dest, int to, int[] src, int from, int len) {
		int bfrom = from / 4;
		int shift = 8 * (from % 4);
		
		for (;;) {
			dest[to++] = (byte)(src[bfrom] >>> shift);
			if (--len == 0) break;
			shift += 8;
			if (shift == 32) {
				shift = 0;
				bfrom++;
			}
		}
	}

	public static void ToBytes(byte[] dest, int to, long[] src, int from, int len) {
		int bfrom = from / 8;
		int shift = 8 * (from % 8);
		
		for (;;) {
			dest[to++] = (byte)(src[bfrom] >>> shift);
			if (--len == 0) break;
			shift += 8;
			if (shift == 64) {
				shift = 0;
				bfrom++;
			}
		}
	}

	public static void FromBytes(short[] dest, int to, byte[] src, int from, int len) {
		int bto = to / 2;
		int shift = 8 * (to % 2);
		short mask = (short)(0xFF << shift);
		short b;
		
		for (;;) {
			b = (short)((src[from++] << shift) & mask);
			dest[bto] &= ~mask;
			dest[bto] |= b;
			if (--len == 0) break;

			shift += 8;
			mask <<= 8;
			if (mask == 0) {
				shift = 0;
				mask = 0xFF;
				bto++;
			}
		}
	}

	public static void FromBytes(int[] dest, int to, byte[] src, int from, int len) {
		int bto = to / 4;
		int shift = 8 * (to % 4);
		int mask = 0xFF << shift;
		int b;
		
		for (;;) {
			b = ((int)src[from++] << shift) & mask;
			dest[bto] &= ~mask;
			dest[bto] |= b;
			if (--len == 0) break;

			shift += 8;
			mask <<= 8;
			if (mask == 0) {
				shift = 0;
				mask = 0xFF;
				bto++;
			}
		}
	}

	public static void FromBytes(long[] dest, int to, byte[] src, int from, int len) {
		int bto = to / 8;
		int shift = 8 * (to % 8);
		long mask = 0xFFL << shift;
		long b;
		
		for (;;) {
			b = ((long)src[from++] << shift) & mask;
			dest[bto] &= ~mask;
			dest[bto] |= b;
			if (--len == 0) break;

			shift += 8;
			mask <<= 8;
			if (mask == 0) {
				shift = 0;
				mask = 0xFF;
				bto++;
			}
		}
	}
	
	
	public static byte[] UuidToBytes(UUID uuid) {
		byte[] ret = new byte [16];
		UuidToBytes(ret, 0, uuid);
		return ret;
	}
	
	public static void UuidToBytes(byte[] dest, int start, UUID uuid) {
		long ul = uuid.getMostSignificantBits();
		dest[start + 0] = (byte)(ul >>> 32);
		dest[start + 1] = (byte)(ul >>> 40);
		dest[start + 2] = (byte)(ul >>> 48);
		dest[start + 3] = (byte)(ul >>> 56);
		dest[start + 4] = (byte)(ul >>> 16);
		dest[start + 5] = (byte)(ul >>> 24);
		dest[start + 6] = (byte)ul;
		dest[start + 7] = (byte)(ul >>> 8);
		
		ul = uuid.getLeastSignificantBits();
		dest[start + 8] = (byte)(ul >>> 56);
		dest[start + 9] = (byte)(ul >>> 48);
		dest[start + 10] = (byte)(ul >>> 40);
		dest[start + 11] = (byte)(ul >>> 32);
		dest[start + 12] = (byte)(ul >>> 24);
		dest[start + 13] = (byte)(ul >>> 16);
		dest[start + 14] = (byte)(ul >>> 8);
		dest[start + 15] = (byte)ul;
	}
	
	public static UUID UuidFromBytes(byte[] src, int start) {
		long msl	= (((long)src[start + 0] & 0xFF) << 32) |
								(((long)src[start + 1] & 0xFF) << 40) |
								(((long)src[start + 2] & 0xFF) << 48) |
								(((long)src[start + 3] & 0xFF) << 56) |
								(((long)src[start + 4] & 0xFF) << 16) |
								(((long)src[start + 5] & 0xFF) << 24) |
								 ((long)src[start + 6] & 0xFF) |
								(((long)src[start + 7] & 0xFF) << 8);

		long lsl	= (((long)src[start + 8] & 0xFF) << 56) |
								(((long)src[start + 9] & 0xFF) << 48) |
								(((long)src[start + 10] & 0xFF) << 40) |
								(((long)src[start + 11] & 0xFF) << 32) |
								(((long)src[start + 12] & 0xFF) << 24) |
								(((long)src[start + 13] & 0xFF) << 16) |
								(((long)src[start + 14] & 0xFF) << 8) |
								 ((long)src[start + 15] & 0xFF);
		
		UUID ret = new UUID(msl, lsl);
		return ret;
	}
	
	
	public static short GetAsShort(byte[] src, int start) {
		return (short)((src[start] & 0xFF) | ((src[start + 1] << 8) & 0xFF00));
	}
	
	
	public static int GetAsInt(byte[] src, int start) {
		return (src[start] & 0xFF) |
					((src[start + 1] << 8) & 0xFF00) |
					((src[start + 2] << 16) & 0xFF0000) |
					((src[start + 3] << 24) & 0xFF000000);
	}
	
	
	public static long GetAsLong(byte[] src, int start) {
		return ((long)src[start] & 0xFFL) |
					(((long)src[start + 1] << 8) & 0xFF00L) |
					(((long)src[start + 2] << 16) & 0xFF0000L) |
					(((long)src[start + 3] << 24) & 0xFF000000L) |
					(((long)src[start + 4] << 32) & 0xFF00000000L) |
					(((long)src[start + 5] << 40) & 0xFF0000000000L) |
					(((long)src[start + 6] << 48) & 0xFF000000000000L) |
					(((long)src[start + 7] << 56) & 0xFF00000000000000L);
	}
	
	
	public static byte[] ShortAsBytes(short val) {
		byte[] ret = new byte [2];
		ret[0] = (byte)val;
		ret[1] = (byte)(val >> 8);
		return ret;
	}
	
	
	public static void ShortAsBytes(short val, byte[] dst, int start) {
		dst[start] = (byte)val;
		dst[start + 1] = (byte)(val >> 8);
	}
	
	
	public static byte[] IntAsBytes(int val) {
		byte[] ret = new byte [4];
		ret[0] = (byte)val;
		ret[1] = (byte)(val >> 8);
		ret[2] = (byte)(val >> 16);
		ret[3] = (byte)(val >> 24);
		return ret;
	}
	
	
	public static void IntAsBytes(int val, byte[] dst, int start) {
		dst[start] = (byte)val;
		dst[start + 1] = (byte)(val >> 8);
		dst[start + 2] = (byte)(val >> 16);
		dst[start + 3] = (byte)(val >> 24);
	}
	
	
	public static byte[] LongAsBytes(long val) {
		byte[] ret = new byte [8];
		ret[0] = (byte)val;
		ret[1] = (byte)(val >> 8);
		ret[2] = (byte)(val >> 16);
		ret[3] = (byte)(val >> 24);
		ret[4] = (byte)(val >> 32);
		ret[5] = (byte)(val >> 40);
		ret[6] = (byte)(val >> 48);
		ret[7] = (byte)(val >> 56);
		return ret;
	}
	
	
	public static void LongAsBytes(long val, byte[] dst, int start) {
		dst[start] = (byte)val;
		dst[start + 1] = (byte)(val >> 8);
		dst[start + 2] = (byte)(val >> 16);
		dst[start + 3] = (byte)(val >> 24);
		dst[start + 4] = (byte)(val >> 32);
		dst[start + 5] = (byte)(val >> 40);
		dst[start + 6] = (byte)(val >> 48);
		dst[start + 7] = (byte)(val >> 56);
	}
}
