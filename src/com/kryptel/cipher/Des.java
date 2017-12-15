/*******************************************************************************

  Product:       Kryptel/Java
  File:          Des.java
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
import static com.kryptel.Guids.CID_CIPHER_DES;

import java.util.UUID;


final class Des extends DesImpl {
	Des(long capabilities) {
		super(capabilities);

  	cipherInfo = new CipherInfo(
  			new int[] { DES_KEY_SIZE },				// Key sizes
  			new int[] { DES_BLOCK_SIZE },				// Block sizes
  			new int[] { DES_ROUNDS },				// Rounds
  			new String[] { "Standard" });
  	
  	DEFAULT_KEY_SIZE = DES_KEY_SIZE;
  	DEFAULT_BLOCK_SIZE = DES_BLOCK_SIZE;
  	DEFAULT_ROUNDS = DES_ROUNDS;
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
	public String ComponentName() { return "DES"; }

	
  //
  // Private data and methods
  //

  static long componentType = TYPE_BLOCK_CIPHER | TYPE_HIDDEN_COMPONENT;
  static UUID componentID = CID_CIPHER_DES;
	
	private static final int DES_KEY_SIZE = 7;

	
	//
	// These methods actually implement the block cipher
	//

  private int[][] Subkeys = new int[2][16];


  protected void ExpandKey() {
    DesExpandKey56(cipherKey, 0, Subkeys);
  }

  protected void EncryptBasicBlock(byte[] dst, int to, byte[] src, int from) {
    DesEncryptBlock(Subkeys, dst, to, src, from);
  }

  protected void DecryptBasicBlock(byte[] dst, int to, byte[] src, int from) {
    DesDecryptBlock(Subkeys, dst, to, src, from);
  }
}
