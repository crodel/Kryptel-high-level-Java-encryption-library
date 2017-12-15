/*******************************************************************************

  Product:       Kryptel/Java
  File:          IFileSystemAttributes.java
  Description:   https://www.kryptel.com/articles/developers/java/storage.ifilesystemattributes.php

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


public interface IFileSystemAttributes {
	IEncryptedDirectory GetParent() throws Exception;

	String GetUniqueName() throws Exception;
	String GetName() throws Exception;
	void SetName(String name) throws Exception;
	
	long GetTime() throws Exception;
	void SetTime(long ftime) throws Exception;

	String GetDescription() throws Exception;
	void SetDescription(String descr) throws Exception;
	
	long GetAttributes() throws Exception;							// Low 32 bits are system-specific attributes and high 32 bits are EFFL_* flags
	void SetAttributes(int attr) throws Exception;			// Set system-specific attributes (not all implementations support them)
}
