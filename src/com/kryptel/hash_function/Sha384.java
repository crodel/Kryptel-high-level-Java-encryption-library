/*******************************************************************************

  Product:       Kryptel/Java
  File:          Sha384.java
  Description:   https://www.kryptel.com/articles/developers/java/hash.php

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


package com.kryptel.hash_function;


import static com.kryptel.Guids.CID_HASH_SHA384;

import java.security.MessageDigest;
import java.util.UUID;


final class Sha384 extends HashBase {
	Sha384(long capabilities) throws Exception {
		super(capabilities);

  	DEFAULT_HASH_SIZE = HASH_SIZE;
  	DEFAULT_PASSES = 1;
  	DEFAULT_SCHEME = 1;

  	hashFunctionInfo = new HashFunctionInfo(
  			new int[] { HASH_SIZE },				// Hash sizes
  			new int[] { DEFAULT_PASSES },		// Passes
  			new String[] { "Standard" });

		hashSize = DEFAULT_HASH_SIZE;
		hashPasses = DEFAULT_PASSES;
		hashScheme = DEFAULT_SCHEME;
		
		sha384 =  MessageDigest.getInstance("SHA-384");
	}
	
	//
	// IKryptelComponent
	//

	public UUID ComponentID() { return componentID; }
	public String ComponentName() { return "SHA-384"; }

	
	//
	// IHashFunctionParams
	//
	
	public int GetHashBlockSize() { return 128; }
	
	
  //
  // Private data and methods
  //

  static UUID componentID = CID_HASH_SHA384;

	private static final int HASH_SIZE = 384 / 8;
 	
	
	//
	// Actual SHA-384 implementation
	//

	private MessageDigest sha384;

  protected void InitImpl() {
  	sha384.reset();
  }
  
  protected void HashImpl(byte[] buffer, int start, int size) {
  	sha384.update(buffer, start, size);
  }
  
  protected byte[] DoneImpl() {
  	return sha384.digest();
  }
}
