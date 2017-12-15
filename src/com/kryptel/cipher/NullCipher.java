/*******************************************************************************

  Product:       Kryptel/Java
  File:          NullCipher.java
  Description:   https://www.kryptel.com/articles/developers/java/cipher.php

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


package com.kryptel.cipher;


import static com.kryptel.Constants.TYPE_BLOCK_CIPHER;
import static com.kryptel.Constants.TYPE_HIDDEN_COMPONENT;
import static com.kryptel.Guids.CID_NULL_CIPHER;

import java.util.UUID;


final class NullCipher extends BlockCipherBase {
	NullCipher(long capabilities) {
		super(capabilities);

  	cipherInfo = new CipherInfo(
			new int[] { 7, 8, 12, 16, 20, 24, 32, 48, 64 },			// Key sizes
			new int[] { 8, 16, 24, 32, 64 },										// Block sizes
			new int[] { 1 },																		// Rounds
			new String[] { "Copying" });
  	
  	DEFAULT_KEY_SIZE = 32;
  	DEFAULT_BLOCK_SIZE = 16;
  	DEFAULT_ROUNDS = 1;
  	DEFAULT_SCHEME = 1;

		cipherKeySize = DEFAULT_KEY_SIZE;
	  cipherBlockSize = DEFAULT_BLOCK_SIZE;
	  cipherRounds = DEFAULT_ROUNDS;
	  cipherScheme = DEFAULT_SCHEME;
	}

	//
	// IKryptelComponent
	//

	public long ComponentType() { return componentType; }
	public UUID ComponentID() { return componentID; }
	public String ComponentName() { return "Null Cipher"; }

	
  //
  // Private data and methods
  //

  static long componentType = TYPE_BLOCK_CIPHER | TYPE_HIDDEN_COMPONENT;
  static final UUID componentID = CID_NULL_CIPHER;
	
	
	//
	// These methods actually implement the block cipher
	//

  protected void ExpandKey() { }
	
  protected void EncryptBasicBlock(byte[] dst, int to, byte[] src, int from) {
		if (dst != src) System.arraycopy(src, from, dst, to, cipherBlockSize);
	}
	
  protected void DecryptBasicBlock(byte[] dst, int to, byte[] src, int from) {
		if (dst != src) System.arraycopy(src, from, dst, to, cipherBlockSize);
	}
}
