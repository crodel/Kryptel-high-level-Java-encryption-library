/*******************************************************************************

  Product:       Kryptel/Java
  File:          ApiHelpers.java
  Description:   https://www.kryptel.com/articles/developers/java/kryptel_api.apihelpers.php

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


package com.kryptel;


import static com.kryptel.Capabilities.CAP_DEFAULT_CAPABILITIES;
import static com.kryptel.Constants.DEFAULT_BUFFER_SIZE;
import static com.kryptel.Guids.IID_IMemoryBlockHash;
import static com.kryptel.IProgressCallback.MIN_SIZE_TO_STEP;
import static com.kryptel.IProgressCallback.NO_TOTAL_PROGRESS_BAR;
import static com.kryptel.IProgressCallback.PROGRESS_STEPS;
import static com.kryptel.KeyIdent.IDENT_FILE_BASED_KEY;
import static com.kryptel.KeyIdent.IDENT_INVALID_KEY;
import static com.kryptel.KeyIdent.IDENT_LOWERCASE_PASSWORD;
import static com.kryptel.KeyIdent.IDENT_NULL;
import static com.kryptel.KeyIdent.IDENT_PASSWORD;
import static com.kryptel.KeyIdent.IDENT_PROTECTED_KEY;
import static com.kryptel.KeyIdent.IDENT_PUBLIC_KEY;
import static com.kryptel.KeyIdent.IDENT_RAW_BINARY_KEY;
import static com.kryptel.KeyIdent.IDENT_YUBIKEY;
import static com.kryptel.KeyIdent.IDENT_YUBIKEY_PASSWORD;

import java.io.RandomAccessFile;
import java.util.UUID;

import com.kryptel.exceptions.UserAbortException;
import com.kryptel.hash_function.IHashFunction;
import com.kryptel.hash_function.IMemoryBlockHash;


public final class ApiHelpers {
	
	public static String NormalizePassword(String password) {
		StringBuilder sb = new StringBuilder(password);
		
		while (sb.length() > 0 && Character.isWhitespace(sb.charAt(0))) sb.deleteCharAt(0);
		while (sb.length() > 0 && Character.isWhitespace(sb.charAt(sb.length() - 1))) sb.deleteCharAt(sb.length() - 1);
		
		// Search for sequences of whitespaces and replace them with a single space
		for (int i = 0; i < sb.length(); i++) {
			if (Character.isWhitespace(sb.charAt(i))) {
				while (Character.isWhitespace(sb.charAt(i))) sb.deleteCharAt(i);
				sb.insert(i, ' ');
			}
		}
		
		return sb.toString();
	}

	
	public static KeyRecord PasswordToKeyRecord(String password, UUID hashCID) throws Exception {
		IKryptelComponent hashComp = com.kryptel.hash_function.ComponentLoader.CreateComponent(hashCID, CAP_DEFAULT_CAPABILITIES);
		if (hashComp == null) throw new Exception(Message.Get(Message.Code.CompNotFound));
		KeyRecord key =  PasswordToKeyRecord(password, hashComp);
		hashComp.DiscardComponent();
		return key;
	}

	
	public static KeyRecord PasswordToKeyRecord(String password, IKryptelComponent hashComp) throws Exception {
		String normalPassword = NormalizePassword(password);
		if (normalPassword.isEmpty()) throw new Exception(Message.Get(Message.Code.EmptyPassword));
		
		KeyRecord key = new KeyRecord();
		IMemoryBlockHash blockHash = (IMemoryBlockHash)hashComp.GetInterface(IID_IMemoryBlockHash);
		
		key.keyMaterial = KeyIdent.IDENT_PASSWORD;
		key.password = normalPassword;
		key.keyData = blockHash.HashWideString(normalPassword);
		
		return key;
	}
	
	
	public static void ConvertPassword(KeyRecord keyRecord, UUID hashCID) throws Exception {
		IKryptelComponent hashComp = com.kryptel.hash_function.ComponentLoader.CreateComponent(hashCID, CAP_DEFAULT_CAPABILITIES);
		if (hashComp == null) throw new Exception(Message.Get(Message.Code.CompNotFound));
		ConvertPassword(keyRecord, hashComp);
		hashComp.DiscardComponent();
	}
	
	
	public static void ConvertPassword(KeyRecord keyRecord, IKryptelComponent hashComp) throws Exception {
		assert keyRecord.keyMaterial.equals(IDENT_PASSWORD) || keyRecord.keyMaterial.equals(IDENT_LOWERCASE_PASSWORD) || keyRecord.keyMaterial.equals(IDENT_PROTECTED_KEY);
		String password = keyRecord.keyMaterial.equals(IDENT_LOWERCASE_PASSWORD) ? keyRecord.password.toLowerCase() : keyRecord.password;
		String normalPassword = NormalizePassword(password);
		if (normalPassword.isEmpty()) throw new Exception(Message.Get(Message.Code.EmptyPassword));

		IMemoryBlockHash blockHash = (IMemoryBlockHash)hashComp.GetInterface(IID_IMemoryBlockHash);
		keyRecord.password = normalPassword;
		keyRecord.keyData = blockHash.HashWideString(normalPassword);
	}
	
	
	public static int ExpectedKeyMaterial(UUID keyMaterial) throws Exception {
		if (keyMaterial.equals(IDENT_NULL)) return IKeyCallback.ANY_KEY_MATERIAL;
		else if (keyMaterial.equals(IDENT_INVALID_KEY)) throw new Exception(Message.Get(Message.Code.InvalidKeyMaterial));
		else if (keyMaterial.equals(IDENT_RAW_BINARY_KEY)) return IKeyCallback.USER_DEFINED_KEY;
		else if (keyMaterial.equals(IDENT_FILE_BASED_KEY)) return IKeyCallback.FILE_BASED_KEY;
		else if (keyMaterial.equals(IDENT_PROTECTED_KEY)) return IKeyCallback.PROTECTED_KEY;
		else if (keyMaterial.equals(IDENT_PUBLIC_KEY)) return IKeyCallback.PUBLIC_KEY;
		else if (keyMaterial.equals(IDENT_PASSWORD)) return IKeyCallback.PASSWORD;
		else if (keyMaterial.equals(IDENT_LOWERCASE_PASSWORD)) return IKeyCallback.LOWERCASE_PASSWORD;
		else if (keyMaterial.equals(IDENT_YUBIKEY)) return IKeyCallback.YUBIKEY;
		else if (keyMaterial.equals(IDENT_YUBIKEY_PASSWORD)) return IKeyCallback.YUBIKEY_PASSWORD;
		return IKeyCallback.BINARY_KEY;
	}

	
	public static byte[] ComputeAreaHash(RandomAccessFile dataFile, long start, long size, IHashFunction hashFunc, Object arg, IProgressCallback progressFunc, Message.Code progressMessageCode) throws Exception {
		String progressMessage = Message.Get(progressMessageCode);
		long[] steps = new long [PROGRESS_STEPS + 1];
		long curPos = 0;
		int curStep = 0;
		boolean bProgress = progressFunc != null && size >= MIN_SIZE_TO_STEP;
		
		try {
			if (bProgress) {
				for (int i = 1; i < PROGRESS_STEPS; i++) steps[i] = (size * i) / PROGRESS_STEPS;
				steps[PROGRESS_STEPS] = size;
				if (!progressFunc.Callback(arg, progressMessage, 0, NO_TOTAL_PROGRESS_BAR)) throw new UserAbortException();
			}
	
			hashFunc.Init();
	
			byte[] buf = new byte [DEFAULT_BUFFER_SIZE];
			int len;
			
			dataFile.seek(start);
			while (size > 0) {
				len = (int)Math.min(buf.length, size);
				dataFile.read(buf, 0, len);
				hashFunc.Hash(buf, 0, len);
				size -= len;
	
				if (bProgress) {
					curPos += len;
					int prevStep = curStep;
					for ( ; curStep < PROGRESS_STEPS && curPos >= steps[curStep + 1]; curStep++);
					if (curStep != prevStep) {
						if (!progressFunc.Callback(arg, progressMessage, curStep, NO_TOTAL_PROGRESS_BAR)) throw new Exception(Message.Get(Message.Code.UserAbort));
					}
				}
			}
			
			return hashFunc.Done();
		}
		finally {
			if (bProgress) progressFunc.Callback(arg, progressMessage, PROGRESS_STEPS, NO_TOTAL_PROGRESS_BAR);	// Make sure progress bar is removed
		}
	}
}
