/*******************************************************************************

  Product:       Kryptel/Java
  File:          IEncryptedDirectory.java
  Description:   https://www.kryptel.com/articles/developers/java/storage.iencrypteddirectory.php

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


import com.kryptel.ICompressionLevelCallback;
import com.kryptel.IProgressCallback;
import com.kryptel.IReplaceCallback;


public interface IEncryptedDirectory extends IFileSystemAttributes {
	IEncryptedDirectory[] GetDirectories() throws Exception;
	IEncryptedDirectory GetDirectory(String uniquePath, boolean bCreate) throws Exception;

	IEncryptedFile[] GetFiles() throws Exception;
	IEncryptedFile GetFile(String uniqueName, boolean bCreate) throws Exception;
	
	void Move(String name, IEncryptedDirectory dest) throws Exception;
	IFileSystemAttributes Delete(String name, boolean recursive) throws Exception;						// Throws exception if recursive is false and 'name' is non-empty directory. Returns NULL if ESTOR_KEEPS_DELETED_OBJECTS is not supported
	IFileSystemAttributes Undelete(String uniqueName, boolean recursive) throws Exception;		// If 'name' is non-empty directory, 'recursive' controls restoring of contained items. Undeleting may cause the item to be renamed, use the returned pointer to get the actual name.
	
	// The Decrypt function decrypts this directory and all its contents
	void Decrypt(String targetDir, Object arg, IReplaceCallback replaceCallback, IProgressCallback progressFunc) throws Exception;		// If targetDir is null, then restore to original path; arg is an application-defined parameter to be passed to callbacks
	
	// Add to current directory
	void StartEncryptionBatch() throws Exception;
	void AddToEncryptionBatch(String path) throws Exception;
	void EncryptBatch(Object arg, IReplaceCallback replaceCallback, IProgressCallback progressFunc, ICompressionLevelCallback comprLevel) throws Exception;		// arg is an application-defined parameter to be passed to callbacks
	
	// The batch decrypts specified children, not this directory
	void StartDecryptionBatch(String targetDir) throws Exception;				// If targetDir is NULL, then restore to original path
	void AddToDecryptionBatch(String uniquePath) throws Exception;			// uniquePath is relative to this directory
	void DecryptBatch(Object arg, IReplaceCallback replaceCallback, IProgressCallback progressFunc) throws Exception;		// arg is an application-defined parameter to be passed to callbacks
}
