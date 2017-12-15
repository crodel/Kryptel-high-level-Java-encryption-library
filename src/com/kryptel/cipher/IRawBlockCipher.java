/*******************************************************************************

  Product:       Kryptel/Java
  File:          IRawBlockCipher.java
  Description:   https://www.kryptel.com/articles/developers/java/cipher.irawblockcipher.php

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


//IRawBlockCipher implementations must allow in-place processing when dst and src point to the same memory area

public interface IRawBlockCipher {
	void EncryptBlock(byte[] dst, int to, byte[] src, int from) throws Exception;
	void DecryptBlock(byte[] dst, int to, byte[] src, int from) throws Exception;
}
