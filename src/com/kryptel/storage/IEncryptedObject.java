/*******************************************************************************

  Product:       Kryptel/Java
  File:          IEncryptedObject.java
  Description:   https://www.kryptel.com/articles/developers/java/storage.iencryptedobject.php

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


public interface IEncryptedObject {
	UUID GetObjectID() throws Exception;
	IEncryptedObject GetParent() throws Exception;
	int GetObjectFlags() throws Exception;
	
	byte[] GetAttributeBlock() throws Exception;
	void SetAttributeBlock(byte[] attr, int start, int size) throws Exception;
	
	boolean StreamExists() throws Exception;
	long StreamSize() throws Exception;
	IEncryptedStream CreateStream(byte comprLevel) throws Exception;
	IEncryptedStream CreateStream(byte[] recData, byte comprLevel) throws Exception;
	IEncryptedStream OpenStream() throws Exception;
	void DeleteStream() throws Exception;
	
	void MoveTo(IEncryptedObject newParent) throws Exception;
	
	UUID[] GetChildren() throws Exception;
	IEncryptedObject CreateChildObject() throws Exception;
	IEncryptedObject GetChildObject(UUID id) throws Exception;
	
	void DeleteChildObject(UUID id) throws Exception;
	void UndeleteChildObject(UUID id, boolean recursive) throws Exception;
}
