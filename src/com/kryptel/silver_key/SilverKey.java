/*******************************************************************************

  Product:       Kryptel/Java
  File:          SilverKey.java
  Description:   https://www.kryptel.com/articles/developers/java/sk.silverkey.php

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


package com.kryptel.silver_key;


import static com.kryptel.Capabilities.CAP_DEFAULT_CAPABILITIES;
import static com.kryptel.Constants.DEFAULT_BUFFER_SIZE;
import static com.kryptel.Guids.CID_HASH_MD5;
import static com.kryptel.Guids.CID_SILVER_KEY;
import static com.kryptel.Guids.CID_SILVER_KEY_FIPS;
import static com.kryptel.Guids.IID_IHashFunction;
import static com.kryptel.bslx.Conversions.GetAsInt;
import static com.kryptel.bslx.Conversions.GetAsLong;
import static com.kryptel.bslx.Conversions.GetAsShort;
import static com.kryptel.bslx.Conversions.UuidFromBytes;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Arrays;
import java.util.UUID;

import com.kryptel.ApiHelpers;
import com.kryptel.IKryptelComponent;
import com.kryptel.IProgressCallback;
import com.kryptel.Message;
import com.kryptel.hash_function.IHashFunction;


public final class SilverKey {
	public static final int PARCEL_TAG											= 0x7A95FFEB;
	public static final int PARCEL_END_TAG									= 0xEBFF957A;
	
	public static final String TARGET_SEPARATOR							= "|";
	public static final String SK_PATH_SEPARATOR						= "\\";
	
	public static final int MAX_BASE_FILE_COPIES						= 16;		// Max copies of hidden parcel's base file.

	// Parcel flags

	public static final int SK_FLAG_ADMIN_RIGHTS_REQ				= 0x00100000;
	public static final int SK_FLAG_UNINSTALLER							= 0x04000000;
	public static final int SK_FLAG_LOCALIZED_STRINGS				= 0x08000000;
	public static final int SK_FLAG_ASK_DIR									= 0x20000000;
	public static final int SK_FLAG_SHOW_DESCRIPTION				= 0x80000000;

	//Silver Key stream command tags

	public static final int COMMAND_NULL										= 0x7A250000;			// Ignored by stub, used to mark stream end
	public static final int COMMAND_PROGRESS								= 0x7A250001;
	public static final int COMMAND_COMMENT									= 0x7A250012;
	public static final int COMMAND_BACKGROUND							= 0x7A251D10;
	public static final int COMMAND_BACKGROUND_PICTURE			= 0x7A251D11;
	public static final int COMMAND_SPLASH									= 0x7A251D4B;
	public static final int COMMAND_DIRECTORY								= 0x7A254FAE;
	public static final int COMMAND_LINK										= 0x7A25BF00;
	public static final int COMMAND_FILE										= 0x7A25BFC0;
	public static final int COMMAND_DELETE									= 0x7A25C0BF;
	public static final int COMMAND_OPEN										= 0x7A25F005;

	
  //
  // Parcel recognition
  //
	
	public static boolean IsParcel(String fileName) throws IOException {
		return IsParcel(fileName, new ParcelLocator());
	}
	
	
	public static boolean IsParcel(String fileName, ParcelLocator locator) throws IOException {
		RandomAccessFile parcelFile = new RandomAccessFile(fileName, "r");
		boolean isParcel = IsParcel(parcelFile, locator);
		parcelFile.close();
		return isParcel;
	}
	
	
	public static boolean IsParcel(RandomAccessFile parcelFile, ParcelLocator locator) throws IOException {
		byte[] buf = new byte [16];
		
		long filePos;
		long fileSize = parcelFile.length();
		if (fileSize < MIN_PARCEL_SIZE) return false;			// File is too small
		
		// Try to locate header quickly
		parcelFile.seek(fileSize - 16 - 8);
		parcelFile.read(buf, 0, 8);
		filePos = GetAsLong(buf, 0);
		if (filePos > 0 && filePos < (fileSize - MIN_PARCEL_SIZE)) {
			parcelFile.seek(filePos);
			parcelFile.read(buf, 0, 4);
			if (GetAsInt(buf, 0) != PARCEL_TAG) filePos = 0;		// Wrong header position hint in the trailer, search from the beginning
		}
		else
			filePos = 0;		// Wrong header position hint in the trailer, search from the beginning
		
		long tailSize = fileSize - filePos;

		UUID guidEngine, guidParcel;
		short versionCreated, versionRequired;
		long headerPos;

		// Find a valid parcel header

		for (;;) {
			if (tailSize < MIN_PARCEL_SIZE) return false;			// File is too small
			
			// Locate parcel header
			
			headerPos = LocateHeaderTag(parcelFile, filePos, tailSize);
			if (headerPos < 0) return false;
			filePos = headerPos + 1;		// +1 to start next search from the next byte
			tailSize = fileSize - filePos;
			parcelFile.seek(headerPos + 4);		// Skip tag doubleword
			
			// Check version and GUID
			
			parcelFile.read(buf, 0, 2);
			versionCreated = GetAsShort(buf, 0);
			parcelFile.read(buf, 0, 2);
			versionRequired = GetAsShort(buf, 0);
			if (versionCreated < 0x0600 || versionRequired < 0x0600 || versionCreated < versionRequired) continue;
			
			parcelFile.read(buf);
			guidEngine = UuidFromBytes(buf, 0);
			if (!guidEngine.equals(CID_SILVER_KEY) && !guidEngine.equals(CID_SILVER_KEY_FIPS)) continue;
			parcelFile.read(buf);
			guidParcel = UuidFromBytes(buf, 0);
			
			break;		// If we reach this point, then a valid header is found
		}
		
		// We have found a valid header and now we are searching backward to find a matching trailer
		
		long trailerPos = fileSize;
		
		for (;;) {
			// Locate parcel end tag (file is scanned backward)

			trailerPos = LocateTrailerTag(parcelFile, headerPos, trailerPos - 1);
			if (trailerPos < 0) return false;

			parcelFile.seek(trailerPos + 4);		// Skip tag doubleword
			UUID guid;
			parcelFile.read(buf);
			guid = UuidFromBytes(buf, 0);
			if (guid.equals(guidParcel)) break;
		}
		
		// We have found a matching header/trailer pair

		trailerPos += 4 + 16 + 3 *8;		// Point to MD5 signature
		
		locator.parcelStart = headerPos;
		locator.parcelSize = trailerPos - headerPos;
		locator.guidEngine = guidEngine;
		locator.versionCreated = versionCreated;
		locator.versionRequired = versionRequired;
		return true;
	}	

	
	public static boolean VerifyParcelMD5(RandomAccessFile parcelFile, ParcelLocator locator) throws Exception {
		return VerifyParcelMD5(parcelFile, locator, null, null, null);
	}

	
	public static boolean VerifyParcelMD5(RandomAccessFile parcelFile, ParcelLocator locator, Object arg, IProgressCallback progressFunc, Message.Code progressMessageCode) throws Exception {
		try (IKryptelComponent md5Comp = com.kryptel.hash_function.ComponentLoader.CreateComponent(CID_HASH_MD5, CAP_DEFAULT_CAPABILITIES);) {
			byte[] computedhash = ApiHelpers.ComputeAreaHash(parcelFile, locator.parcelStart, locator.parcelSize,
					(IHashFunction)md5Comp.GetInterface(IID_IHashFunction), arg, progressFunc, progressMessageCode);

			byte[] hashRead = new byte [16];
			parcelFile.seek(locator.parcelStart + locator.parcelSize);
			parcelFile.read(hashRead, 0, 16);

			return Arrays.equals(computedhash, hashRead);
		}
	}
	
	
	public static String GetStubDirectory() { return strStubDirectory; }
	public static void SetStubDirectory(String stubDir) { strStubDirectory = stubDir; }
	
	
  //
  // Private data and methods
  //
	
	private static final int MIN_PARCEL_SIZE = 128;				// A very rough estimate of minimum parcel size
	private static final int BUFFER_TAIL_SIZE = 3;		// sizeof(int) - 1
	
	private static String strStubDirectory = "." + File.separator + "Stubs" + File.separator;
	

	// Caller provides sufficient workingBuf to avoid multiple allocation
	private static void ReadBackward(RandomAccessFile parcelFile, byte[] buffer, int start, int size, byte[] workingBuf) throws IOException {
		long startPos = parcelFile.getFilePointer();
		assert (startPos >= size);
		parcelFile.seek(startPos - size);
		parcelFile.read(workingBuf, 0, size);
		parcelFile.seek(startPos - size);
		for (int i = 0, j = size; i < size; i++) buffer[start + i] = workingBuf[--j];
	}
	
	
	// If retVal >= 0, header tag was found at retVal
	// Otherwise header tag was not found
	private static long LocateHeaderTag(RandomAccessFile parcelFile, long filePos, long fileSize) throws IOException {
		byte[] buf = new byte [DEFAULT_BUFFER_SIZE];
		long pos = filePos;
		long size = fileSize;
		int bytesRead, bytesToCheck;
		int readPos = 0;
		
		// Locate parcel start tag
		
		parcelFile.seek(filePos);
		while (size > 0) {
			bytesRead = (int)Math.min((buf.length - readPos), size);
			parcelFile.read(buf, readPos, bytesRead);
			size -= bytesRead;

			bytesToCheck = readPos + bytesRead - BUFFER_TAIL_SIZE;
			for (int i = 0; i < bytesToCheck; i++) {
				if (GetAsInt(buf, i) == PARCEL_TAG) return pos + i;
			}

			System.arraycopy(buf, bytesToCheck, buf, 0, BUFFER_TAIL_SIZE);
			readPos = BUFFER_TAIL_SIZE;
			pos += bytesToCheck;
		}
		
		return -1;
	}
	
	
	// Scans file backward starting from endPos
	// If retVal >= 0, trailer tag was found at retVal
	// Otherwise trailer tag was not found
	private static long LocateTrailerTag(RandomAccessFile parcelFile, long beginPos, long endPos) throws IOException {
		final int reversedTag = ((PARCEL_END_TAG << 24) & 0xFF000000) | ((PARCEL_END_TAG << 8) & 0x00FF0000) | ((PARCEL_END_TAG >>> 8) & 0x0000FF00) | ((PARCEL_END_TAG >>> 24) & 0x000000FF);		// Reversed bytes
		long size = endPos - beginPos;
		if (size <= MIN_PARCEL_SIZE) return -1;
		size -= MIN_PARCEL_SIZE;
		long pos = endPos;

		byte[] buf = new byte [DEFAULT_BUFFER_SIZE];
		byte[] workingBuf = new byte [DEFAULT_BUFFER_SIZE];
		int bytesRead, bytesToCheck;
		int readPos = 0;

		parcelFile.seek(endPos);
		while (size > 0) {
			bytesRead = (int)Math.min((buf.length - readPos), size);
			ReadBackward(parcelFile, buf, readPos, bytesRead, workingBuf);
			size -= bytesRead;

			bytesToCheck = readPos + bytesRead - BUFFER_TAIL_SIZE;
			for (int i = 0; i < bytesToCheck; i++) {
				if (GetAsInt(buf, i) == reversedTag) return pos - i - 4;		// 4 is sizeof(int)
			}

			System.arraycopy(buf, bytesToCheck, buf, 0, BUFFER_TAIL_SIZE);
			readPos = BUFFER_TAIL_SIZE;
			pos -= bytesToCheck;
		}
		
		return -1;
	}
}
