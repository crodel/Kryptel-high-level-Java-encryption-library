/*******************************************************************************

  Product:       Kryptel/Java
  File:          IEncryptedStorageInfo.java
  Description:   https://www.kryptel.com/articles/developers/java/storage.iencryptedstorageinfo.php

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


package com.kryptel.storage;


import java.util.UUID;

import com.kryptel.cipher.CipherParameters;
import com.kryptel.compressor.CompressorParameters;
import com.kryptel.hash_function.HashFunctionParameters;


public interface IEncryptedStorageInfo {
	int GetStorageCapabilities() throws Exception;
	StorageStatistics GetStorageStatistics() throws Exception;
	
	byte[] GetAgentData() throws Exception;
	
	UUID GetCipherCID() throws Exception;
	CipherParameters GetCipherParameters() throws Exception;
	String GetCipherName() throws Exception;
	String GetCipherScheme() throws Exception;
	
	UUID GetCompressorCID() throws Exception;
	CompressorParameters GetCompressorParameters() throws Exception;
	String GetCompressorName() throws Exception;
	String GetCompressorScheme() throws Exception;
	
	UUID GetHashFunctionCID() throws Exception;
	HashFunctionParameters GetHashFunctionParameters() throws Exception;
	String GetHashFunctionName() throws Exception;
	String GetHashFunctionScheme() throws Exception;
	
	UUID GetKeyID() throws Exception;
	String GetKeyPath() throws Exception;
	
	boolean TestPassword(String password) throws Exception;
}
