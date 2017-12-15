/*******************************************************************************

  Product:       Kryptel/Java
  File:          IEncryptedStorage.java
  Description:   https://www.kryptel.com/articles/developers/java/storage.iencryptedstorage.php

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


public interface IEncryptedStorage {
	enum CONTAINER_COMPRESSION_STRATEGY { KRCONT_COMPRESS_NEVER, KRCONT_COMPRESS_ALWAYS, KRCONT_COMPRESS_SMART };
	enum CONTAINER_ACCESS_MODE { CONT_READ_WRITE, CONT_READ_ONLY, CONT_ANY };
	
	static final CONTAINER_COMPRESSION_STRATEGY DEFAULT_COMPRESSION_STRATEGY = CONTAINER_COMPRESSION_STRATEGY.KRCONT_COMPRESS_SMART;
	
	IEncryptedStorageInfo GetStorageInfo() throws Exception;
	
	CONTAINER_COMPRESSION_STRATEGY SetCompressionStrategy(CONTAINER_COMPRESSION_STRATEGY strategy) throws Exception;
	
	void SetAgentData(byte[] data, int start, int size) throws Exception;
	
	IEncryptedObject Create(String path, IKryptelComponent cipherComp, IKryptelComponent compressorComp, IKryptelComponent hashFuncComp, UUID agent, Object arg, IKeyCallback keyFunc) throws Exception;
	IEncryptedObject Open(String path, CONTAINER_ACCESS_MODE mode, Object arg, IKeyCallback keyFunc) throws Exception;
	
	IEncryptedObject GetRootObject() throws Exception;
	
	boolean IsModified() throws Exception;
	
	void Close() throws Exception;
	void Compress() throws Exception;		// Same as Close if ESTOR_CAN_BE_COMPRESSED is not supported
	void Discard() throws Exception;
}
