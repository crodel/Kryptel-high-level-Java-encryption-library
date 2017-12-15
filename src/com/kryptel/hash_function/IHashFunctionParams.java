/*******************************************************************************

  Product:       Kryptel/Java
  File:          IHashFunctionParams.java
  Description:   https://www.kryptel.com/articles/developers/java/hash.ihashfunctionparams.php

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


public interface IHashFunctionParams {
	int GetHashSize() throws Exception;
	int GetPasses() throws Exception;
	byte GetScheme() throws Exception;
	
	int GetHashBlockSize();		// Used by HMAC, by default it is 64 bytes
	
	void SetHashSize(int size) throws Exception;
	void SetPasses(int passes) throws Exception;
	void SetScheme(byte scheme) throws Exception;
	
	HashFunctionInfo GetInfo() throws Exception;
}
