/*******************************************************************************

  Product:       Kryptel/Java
  File:          ICipherParams.java
  Description:   https://www.kryptel.com/articles/developers/java/cipher.icipherparams.php

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


// IMPORTANT: Schemes are numbered starting with 1; zero value (DEFAULT_VALUE) denotes the 'default' scheme.

public interface ICipherParams {
	int GetKeySize() throws Exception;
	int GetRounds() throws Exception;
	byte GetScheme() throws Exception;
	byte[] GetKey() throws Exception;
	
	void SetKeySize(int size) throws Exception;
	void SetRounds(int rounds) throws Exception;
	void SetScheme(byte scheme) throws Exception;
	void SetKey(byte[] key, int start, int size) throws Exception;
	
	CipherInfo GetInfo() throws Exception;
}
