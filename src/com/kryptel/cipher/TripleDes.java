/*******************************************************************************

  Product:       Kryptel/Java
  File:          TripleDes.java
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


import static com.kryptel.Guids.CID_CIPHER_TRIPLE_DES;

import java.util.UUID;


final class TripleDes extends DesImpl {
	TripleDes(long capabilities) {
		super(capabilities);

  	cipherInfo = new CipherInfo(
  			new int[] { TRIPLE_DES_KEY_SIZE },				// Key sizes
  			new int[] { DES_BLOCK_SIZE },				// Block sizes
  			new int[] { DES_ROUNDS },				// Rounds
  			new String[] { "Encrypt-Decrypt-Encrypt", "Encrypt-Encrypt-Encrypt" });
  	
  	DEFAULT_KEY_SIZE = TRIPLE_DES_KEY_SIZE;
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

	public UUID ComponentID() { return componentID; }
	public String ComponentName() { return "Triple-DES"; }


  //
  // Private data and methods
  //

  static UUID componentID = CID_CIPHER_TRIPLE_DES;

	private static final int TRIPLE_DES_KEY_SIZE = 7 * 3;

	
	//
	// These methods actually implement the block cipher
	//

  private int[][] Subkeys1 = new int[2][16];
  private int[][] Subkeys2 = new int[2][16];
  private int[][] Subkeys3 = new int[2][16];


  protected void ExpandKey() {
    DesExpandKey56(cipherKey, 0, Subkeys1);
    DesExpandKey56(cipherKey, 7, Subkeys2);
    DesExpandKey56(cipherKey, 14, Subkeys3);
  }

  protected void EncryptBasicBlock(byte[] dst, int to, byte[] src, int from) {
  	Des3EncryptBlock(Subkeys1, Subkeys2, Subkeys3, dst, to, src, from);
  }

  protected void DecryptBasicBlock(byte[] dst, int to, byte[] src, int from) {
  	Des3DecryptBlock(Subkeys1, Subkeys2, Subkeys3, dst, to, src, from);
  }
}
