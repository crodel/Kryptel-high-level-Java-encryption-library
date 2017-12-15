/*******************************************************************************

  Product:       Kryptel/Java
  File:          Sha512.java
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


import static com.kryptel.Capabilities.CAP_DEFAULT_CAPABILITIES;
import static com.kryptel.Guids.CID_HASH_SHA512;
import static com.kryptel.Guids.CID_HASH_SHA512_64;

import java.security.MessageDigest;
import java.util.UUID;

import com.kryptel.IKryptelComponent;


final class Sha512 extends HashBase {
	Sha512(long capabilities, boolean bBlock64) throws Exception {
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

		bBlockSize64 = bBlock64;
		sha512 =  MessageDigest.getInstance("SHA-512");
	}
	
	//
	// IKryptelComponent
	//

	public UUID ComponentID() { return bBlockSize64 ? componentID_64 : componentID; }
	public String ComponentName() { return "SHA-512"; }
	
	
	//
	// IComponentState
	//

	public IKryptelComponent Clone() throws Exception {
		Sha512 clone = new Sha512(CAP_DEFAULT_CAPABILITIES, bBlockSize64);
		clone.SetHashSize(GetHashSize());
		clone.SetPasses(GetPasses());
		clone.SetScheme(GetScheme());
		return clone;
	}

	
	//
	// IHashFunctionParams
	//
	
	public int GetHashBlockSize() { return bBlockSize64 ? 64 : 128; }
	
	
  //
  // Private data and methods
  //

  static UUID componentID = CID_HASH_SHA512;
  static UUID componentID_64 = CID_HASH_SHA512_64;

	private static final int HASH_SIZE = 512 / 8;
	
	private boolean bBlockSize64;


	//
	// Actual SHA-512 implementation
	//

	private MessageDigest sha512;

  protected void InitImpl() {
  	sha512.reset();
  }
  
  protected void HashImpl(byte[] buffer, int start, int size) {
  	sha512.update(buffer, start, size);
  }
  
  protected byte[] DoneImpl() {
  	return sha512.digest();
  }
}
