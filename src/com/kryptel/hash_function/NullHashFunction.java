/*******************************************************************************

  Product:       Kryptel/Java
  File:          NullHashFunction.java
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


import static com.kryptel.Constants.TYPE_HASH_FUNCTION;
import static com.kryptel.Constants.TYPE_HIDDEN_COMPONENT;
import static com.kryptel.Guids.CID_NULL_HASH_FUNCTION;

import java.util.UUID;


final class NullHashFunction extends HashBase {
	NullHashFunction(long capabilities) {
		super(capabilities);

  	DEFAULT_HASH_SIZE = 128 / 8;
  	DEFAULT_PASSES = 1;
  	DEFAULT_SCHEME = 1;

  	hashFunctionInfo = new HashFunctionInfo(
  			new int[] { 4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64 },				// Hash sizes
  			new int[] { DEFAULT_PASSES },		// Passes
  			new String[] { "Zero Hash" });

		hashSize = DEFAULT_HASH_SIZE;
		hashPasses = DEFAULT_PASSES;
		hashScheme = DEFAULT_SCHEME;
	}
	
	//
	// IKryptelComponent
	//

	public long ComponentType() { return TYPE_HASH_FUNCTION | TYPE_HIDDEN_COMPONENT; }
	public UUID ComponentID() { return componentID; }
	public String ComponentName() { return "Null Hash Function"; }

	
	//
  // Private data and methods
  //

  static UUID componentID = CID_NULL_HASH_FUNCTION;

	
	//
	// Actual MD5 implementation
	//
	
  protected void InitImpl() { }
  
  protected void HashImpl(byte[] buffer, int start, int size) { }
  
  protected byte[] DoneImpl() {
    return new byte [hashSize];
  }
}
