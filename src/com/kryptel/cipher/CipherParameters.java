/*******************************************************************************

  Product:       Kryptel/Java
  File:          CipherParameters.java
  Description:   https://www.kryptel.com/articles/developers/java/cipher.cipherparameters.php

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

public final class CipherParameters {
	final public int cipherKeySize;
	final public int cipherBlockSize;
	final public int cipherRounds;
	final public byte cipherScheme;
	final public int cipherMode;			// Block chaining mode
	
	public CipherParameters(CipherParameters cp) {
		cipherKeySize = cp.cipherKeySize;
		cipherBlockSize = cp.cipherBlockSize;
		cipherRounds = cp.cipherRounds;
		cipherScheme = cp.cipherScheme;
		cipherMode = cp.cipherMode;
	}
	
	public CipherParameters(int keySize, int blockSize, int rounds, byte scheme, int mode) {
		cipherKeySize = keySize;
		cipherBlockSize = blockSize;
		cipherRounds = rounds;
		cipherScheme = scheme;
		cipherMode = mode;
	}
}
