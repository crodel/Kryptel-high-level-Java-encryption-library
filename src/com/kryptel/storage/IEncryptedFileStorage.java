/*******************************************************************************

  Product:       Kryptel/Java
  File:          IEncryptedFileStorage.java
  Description:   https://www.kryptel.com/articles/developers/java/storage.iencryptedfilestorage.php

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

import com.kryptel.IKeyCallback;
import com.kryptel.IKryptelComponent;
import com.kryptel.storage.IEncryptedStorage.CONTAINER_COMPRESSION_STRATEGY;


public interface IEncryptedFileStorage {
	IEncryptedFileStorageInfo GetFileStorageInfo() throws Exception;
	
	int SetStorageControlFlags(int scFlags) throws Exception;
	CONTAINER_COMPRESSION_STRATEGY SetCompressionStrategy(CONTAINER_COMPRESSION_STRATEGY strategy) throws Exception;

	void SetDescription(String descr) throws Exception;

	String GetEncryptedDescription() throws Exception;
	void SetEncryptedDescription(String descr) throws Exception;
	
	byte[] GetAssociatedData() throws Exception;
	void SetAssociatedData(byte[] adata) throws Exception;

	int[] GetRoots() throws Exception;
	IEncryptedDirectory GetRootDir(int target) throws Exception;
	
	void Create(String path, IKryptelComponent cipher, IKryptelComponent compressor, IKryptelComponent hashFunc, UUID handler, Object keyArg, IKeyCallback keyFunc) throws Exception;
	void Open(String path, IEncryptedStorage.CONTAINER_ACCESS_MODE mode, Object keyArg, IKeyCallback keyFunc) throws Exception;
	
	void Close() throws Exception;
	void Compress() throws Exception;		// Same as Close if ESTOR_CAN_BE_COMPRESSED is not supported
	void Discard() throws Exception;
}
