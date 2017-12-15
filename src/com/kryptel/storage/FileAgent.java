/*******************************************************************************

  Product:       Kryptel/Java
  File:          FileAgent.java

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
import static com.kryptel.Guids.*;
import static com.kryptel.bslx.Targets.*;

import java.io.File;
import java.util.StringTokenizer;
import java.util.UUID;

import com.kryptel.IKeyCallback;
import com.kryptel.IKryptelComponent;


class FileAgent extends Agent {
	FileAgent(long capabilities) throws Exception {
		super(capabilities);
	}

	
	//
	// IKryptelComponent
	//
	
	
	public long ComponentType() { return componentType; }
	
	public UUID ComponentID() { return componentID;	}

	public String ComponentName() { return "Kryptel 7 File Agent"; }

	
	//
	// IEncryptedFileStorage
	//

	
	public byte[] GetAssociatedData() throws Exception {
		throw new Exception("FileAgent::GetAssociatedData : Unsuppported operation.");
	}


	public void SetAssociatedData(byte[] adata) throws Exception {
		throw new Exception("FileAgent::SetAssociatedData : Unsuppported operation.");
	}

	
	public int[] GetRoots() throws Exception {
		if (storageComp == null) throw new Exception("FileAgent::GetRoots : Container is not open.");
		return new int[] { TARGET_DEFAULT };
	}


	public IEncryptedDirectory GetRootDir(int target) throws Exception {
		if (storageComp == null) throw new Exception("FileAgent::GetRootDir : Container is not open.");
		if (target != TARGET_DEFAULT) throw new Exception("FileAgent::GetRootDir : Targets are not supported for this type of agent - use TARGET_DEFAULT.");
		return rootDirectory;
	}

	
	public void Create(String path, IKryptelComponent cipher, IKryptelComponent compressor, IKryptelComponent hashFunc, UUID handler, Object keyArg, IKeyCallback keyFunc) throws Exception {
		rootDirectory = null;
		super.Create(path, cipher, compressor, hashFunc, handler, keyArg, keyFunc);
		rootDirectory = new DirectoryObject(this, rootObject, TARGET_DEFAULT);
	}

	
	public void Open(String path, IEncryptedStorage.CONTAINER_ACCESS_MODE mode, Object keyArg, IKeyCallback keyFunc) throws Exception {
		rootDirectory = null;
		super.Open(path, mode, keyArg, keyFunc);
		rootDirectory = new DirectoryObject(this, rootObject, TARGET_DEFAULT);
	}
	
	
	public void Close() throws Exception {
		rootDirectory = null;
		super.Close();
	}
	
	
	public void Compress() throws Exception {
		rootDirectory = null;
		super.Compress();
	}
	
	
	public void Discard() throws Exception {
		rootDirectory = null;
		super.Discard();
	}


	//
	// IEncryptedStorageInfo
	//


	public FileStorageStatistics GetFileStorageStatistics() throws Exception {
		if (storageComp == null) throw new Exception("FileAgent::GetFileStorageStatistics : Container is not open.");
		FileStorageStatistics stat = new FileStorageStatistics();
		rootDirectory.FillStatisticsBlock(stat);
		return stat;
	}

	
  //
  // Private data and methods
  //

	
  static long componentType = TYPE_STORAGE_AGENT | TYPE_FILE_AGENT;
  
  static UUID componentID = CID_FILE_AGENT;
  
  private DirectoryObject rootDirectory = null;
	
	
	DirectoryObject FindDirectoryObject(IEncryptedDirectory encDir) throws Exception {
		String path = AgentObject.GetItemPath(encDir);
		StringTokenizer tk = new StringTokenizer(path, File.separator);
		DirectoryObject dir = rootDirectory;
		while (tk.hasMoreTokens()) dir = dir.dirMap.get(tk.nextToken());
		return dir;
	}
	
	protected boolean IsBackupAgent() { return false; }
}
