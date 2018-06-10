/*******************************************************************************

  Product:       Kryptel/Java
  File:          BinaryKeyFile.java
  Description:   https://www.kryptel.com/articles/developers/java/key.binarykeyfile.php

  Copyright (c) 2018 Inv Softworks LLC,    http://www.kryptel.com

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


package com.kryptel.key;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;

import com.kryptel.Message;

import static com.kryptel.Constants.*;
import static com.kryptel.Guids.*;
import static com.kryptel.bslx.Conversions.*;


public class BinaryKeyFile {
	
	public static final long NO_TIMESTAMP						= -1;
	public static final long CURRENT_TIMESTAMP			= 0;

	
	public BinaryKeyFile(String filePath) throws Exception {
		File kf = new File(filePath);
		long fsize = kf.length();
		if (fsize < 560 || fsize > 9026) throw new Exception(Message.Get(Message.Code.InvalidKeyFile));
		
		byte[] buf = new byte [(int)fsize];
		try (FileInputStream in = new FileInputStream(kf)) {
			in.read(buf, 0, (int)fsize);
		}
		
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		md5.update(buf, 0, buf.length - 16);
		if (!Arrays.equals(md5.digest(), Arrays.copyOfRange(buf, buf.length - 16, buf.length))) throw new Exception(Message.Get(Message.Code.InvalidKeyFile));
		
		if (!UuidFromBytes(buf, 0).equals(CID_KEY_MANAGER)) throw new Exception(Message.Get(Message.Code.InvalidKeyFile));
		keyGuid = UuidFromBytes(buf, 16);

		keyData = new byte [BINARY_KEY_SIZE];
		System.arraycopy(buf, 32, keyData, 0, BINARY_KEY_SIZE);
			
		if (fsize > 560) {		// Timestamp and possible comment present
			if (fsize < 568) throw new Exception(Message.Get(Message.Code.InvalidKeyFile));
			timeStamp = GetAsLong(buf, 544);
			
			int len = (int)fsize - 568;
			if (len > 0) keyComment = new String(buf, 552, len, "UnicodeLittleUnmarked");
		}
		else
			timeStamp = NO_TIMESTAMP;
	}
	
	
	public BinaryKeyFile(long time, String comment) throws Exception {
		SecureRandom rand = new SecureRandom();
		rand.setSeed(rand.generateSeed(256 / 8));

		byte[] b = new byte [16];
		rand.nextBytes(b);
		keyGuid = UuidFromBytes(b, 0);
		
		keyData = new byte [BINARY_KEY_SIZE];
		rand.nextBytes(keyData);
		
		if (time == NO_TIMESTAMP) {
			timeStamp = NO_TIMESTAMP;
			if (comment != null) throw new Exception("BinaryKeyFile: key file without timestamp can't include a comment.");
		}
		else if (time == CURRENT_TIMESTAMP)
			timeStamp = System.currentTimeMillis();
		else
			timeStamp = time;
		
		keyComment = comment;
	}
	
	
	public UUID GetKeyID() { return keyGuid; }
	
	public byte [] GetKeyData() { return keyData; }
	
	public long GetKeyTimestamp() { return timeStamp; }
	
	public String GetKeyComment() { return keyComment; }
	
	
	public void Save(String filePath) throws Exception {
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		
		File kf = new File(filePath);
		if (kf.exists()) throw new Exception("BinaryKeyFile: Save failed - key file with such name already exists.");
		try (FileOutputStream out = new FileOutputStream(kf)) {
			byte[] b = UuidToBytes(CID_KEY_MANAGER);
			out.write(b);
			md5.update(b, 0, 16);

			b = UuidToBytes(keyGuid);
			out.write(b);
			md5.update(b, 0, 16);

			out.write(keyData);
			md5.update(keyData, 0, BINARY_KEY_SIZE);
	
			if (timeStamp != NO_TIMESTAMP) {
				b = LongAsBytes(timeStamp);
				out.write(b);
				md5.update(b, 0, 8);
				
				if (keyComment != null) {
					b = keyComment.getBytes("UnicodeLittleUnmarked");
					out.write(b);
					md5.update(b, 0, b.length);
				}
			}
			
			b = md5.digest();
			out.write(b);
		}
	}
	
	
	//
	// Private data and methods
	//
	
	private UUID keyGuid;
	private byte[] keyData;
	private long timeStamp;
	private String keyComment;

}
