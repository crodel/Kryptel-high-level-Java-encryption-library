/*******************************************************************************

  Product:       Kryptel/Java
  File:          AgentObject.java

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


import static com.kryptel.Constants.*;
import static com.kryptel.bslx.Conversions.GetAsInt;
import static com.kryptel.storage.Kryptel.*;

import java.io.File;


abstract class AgentObject implements IFileSystemAttributes {

	AgentObject(Agent agent, DirectoryObject parent, IEncryptedObject object) {
		this.agent = agent;
		this.parent = parent;
		storageObject = object;
	}
	
	
	//
	// IFileSystemAttributes
	//
	
	
	public IEncryptedDirectory GetParent() {
		return parent;
	}
	

	public String GetUniqueName() throws Exception {
		return GenerateUniqueName();
	}
	
	
	public String GetName() throws Exception {
		return itemName;
	}
	
	
	public long GetTime() throws Exception {
		return timeStamp;
	}
	
	
	public void SetTime(long ftime) throws Exception {
		if (GetParent() == null) throw new Exception("AgentObject::SetTime : Can't set root directory time.");
		if (IsDeleted()) throw new Exception("AgentObject::SetTime : Can't modify deleted object.");
		timeStamp = ftime;
		SaveAttrBlock();
	}
	

	public String GetDescription() throws Exception {
		return itemDescription;
	}
	
	
	public void SetDescription(String descr) throws Exception {
		if (GetParent() == null) throw new Exception("AgentObject::SetDescription : Can't set root directory description.");
		if (IsDeleted()) throw new Exception("AgentObject::SetDescription : Can't modify deleted object.");
		itemDescription = descr;
		SaveAttrBlock();
	}

	
	//
  // Private data and methods
  //

	
	protected Agent agent;
	protected DirectoryObject parent = null;
	protected IEncryptedObject storageObject;
	
	protected boolean bAttrLoaded = false;
	protected String itemName;
	protected String itemDescription;
	protected long timeStamp;
	
	
	//
	// Local functions
	//
	
	
	protected boolean IsDeleted() throws Exception { return (storageObject.GetObjectFlags() & EFL_OBJECT_DELETED) != 0; }


	protected boolean IsDirectory(IEncryptedObject obj) throws Exception {
		byte[] attrBlock = obj.GetAttributeBlock();
		if (attrBlock.length < 20) throw new Exception("AgentObject::IsDirectory : Invalid size of directory attribute block.");
		return GetAsInt(attrBlock, 0) == ID_DIRECTORY;
	}
	
	
	protected String GenerateUniqueName() throws Exception {
		if (parent != null && IsDeleted())
			return UNIQUE_FILE_NAME_PREFIX + storageObject.GetObjectID().toString();
		else
			return itemName;
	}
	
	
	static String GetItemPath(IEncryptedDirectory dir) throws Exception {
		String path = "";
		for (;;) {
			path = File.separator + dir.GetUniqueName();
			dir = dir.GetParent();
			if (dir == null) break;
		}
		return path;
	}
	
	
	protected void InitAttrBlock(String name) throws Exception {
		InitAttrBlock(name, System.currentTimeMillis() / 1000L);
	}
	
	
	protected void InitAttrBlock(String name, long time) throws Exception {
		itemName = name;
		timeStamp = time;
		bAttrLoaded = true;
		SaveAttrBlock();
	}
	
	protected abstract void FetchAttrBlock() throws Exception;
	
	protected abstract void SaveAttrBlock() throws Exception;
}
