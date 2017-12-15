/*******************************************************************************

  Product:       Kryptel/Java
  File:          IBlockCipherParams.java
  Description:   https://www.kryptel.com/articles/developers/java/cipher.iblockcipherparams.php

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


public interface IBlockCipherParams extends ICipherParams {
	static final int MODE_ECB = 0;
	static final int MODE_CBC = 1;
	static final int MODE_CFB = 2;
	static final int MODE_OFB = 3;
	static final int MODE_CTR = 4;

	int GetBlockSize() throws Exception;
	int GetChainingMode() throws Exception;
	byte[] GetInitVector() throws Exception;
	
	void SetBlockSize(int size) throws Exception;
	void SetChainingMode(int mode) throws Exception;
	void SetInitVector(byte[] vector, int start, int size) throws Exception;
}
