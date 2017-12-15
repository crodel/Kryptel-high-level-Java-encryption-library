/*******************************************************************************

  Product:       Kryptel/Java
  File:          BackupAgent.java

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
import static com.kryptel.bslx.Conversions.*;
import static com.kryptel.bslx.Targets.*;
import static com.kryptel.storage.Kryptel.*;

import java.io.File;
import java.util.HashMap;
import java.util.StringTokenizer;
import java.util.UUID;

import com.kryptel.IKeyCallback;
import com.kryptel.IKryptelComponent;


class BackupAgent extends Agent {
	BackupAgent(long capabilities) throws Exception {
		super(capabilities);
	}

	
	//
	// IKryptelComponent
	//
	
	
	public long ComponentType() { return componentType; }
	
	public UUID ComponentID() { return componentID;	}

	public String ComponentName() { return "Kryptel 7 Backup Agent"; }

	
	//
	// IEncryptedFileStorage
	//

	
	public byte[] GetAssociatedData() throws Exception {
		if (storageComp == null) throw new Exception("BackupAgent::GetAssociatedData : Container is not open.");
		return rootObject.GetAttributeBlock();
	}


	public void SetAssociatedData(byte[] adata) throws Exception {
		if (storageComp == null) throw new Exception("BackupAgent::SetAssociatedData : Container is not open.");
		rootObject.SetAttributeBlock(adata, 0, adata.length);
	}

	
	public int[] GetRoots() throws Exception {
		if (storageComp == null) throw new Exception("BackupAgent::GetRoots : Container is not open.");
		int j = 0;
		int[] retArr = new int [targetMap.size()];
		for (Integer t: targetMap.keySet()) retArr[j++] = t;
		return retArr;
	}


	public IEncryptedDirectory GetRootDir(int target) throws Exception {
		if (storageComp == null) throw new Exception("BackupAgent::GetRootDir : Container is not open.");
		if (target == TARGET_DEFAULT)
			return new BackupRootObject(this);
		else if (!targetMap.containsKey(target))
			return CreateTarget(target);
		else
			return targetMap.get(target);
	}

	
	public void Create(String path, IKryptelComponent cipher, IKryptelComponent compressor, IKryptelComponent hashFunc, UUID handler, Object keyArg, IKeyCallback keyFunc) throws Exception {
		assert targetMap.isEmpty();
		super.Create(path, cipher, compressor, hashFunc, handler, keyArg, keyFunc);
	}

	
	public void Open(String path, IEncryptedStorage.CONTAINER_ACCESS_MODE mode, Object keyArg, IKeyCallback keyFunc) throws Exception {
		assert targetMap.isEmpty();
		super.Open(path, mode, keyArg, keyFunc);
		
		UUID[] uids = rootObject.GetChildren();
		for (UUID uid: uids) {
			IEncryptedObject obj = rootObject.GetChildObject(uid);
			byte[] attr = obj.GetAttributeBlock();
			if (attr.length != 8) throw new Exception("BackupAgent::Open : Invalid size of object's target field.");
			if (GetAsInt(attr, 0) != ID_TARGET) throw new Exception("BackupAgent::Open : Invalid target attributes.");
			int target = GetAsInt(attr, 4);
			targetMap.put(target, new DirectoryObject(this, obj, target));
		}
	}
	
	
	public void Close() throws Exception {
		targetMap.clear();
		super.Close();
	}
	
	
	public void Compress() throws Exception {
		targetMap.clear();
		super.Compress();
	}
	
	
	public void Discard() throws Exception {
		targetMap.clear();
		super.Discard();
	}


	//
	// IEncryptedStorageInfo
	//


	public FileStorageStatistics GetFileStorageStatistics() throws Exception {
		if (storageComp == null) throw new Exception("BackupAgent::GetFileStorageStatistics : Container is not open.");
		FileStorageStatistics stat = new FileStorageStatistics();
		for (DirectoryObject d: targetMap.values()) d.FillStatisticsBlock(stat);
		return stat;
	}

	
  //
  // Private data and methods
  //

	
  static long componentType = TYPE_STORAGE_AGENT | TYPE_BACKUP_AGENT;
  
  static UUID componentID = CID_BACKUP_AGENT;
  
  HashMap<Integer, DirectoryObject> targetMap = new HashMap<Integer, DirectoryObject>(); 
	
  
	protected boolean IsBackupAgent() { return true; }


	DirectoryObject FindDirectoryObject(IEncryptedDirectory encDir) throws Exception {
		String path = AgentObject.GetItemPath(encDir);
		StringTokenizer tk = new StringTokenizer(path, File.separator);
		DirectoryObject dir = null;
		String targetName = tk.nextToken();
		for (Integer t: targetMap.keySet()) {
			if (GetTargetName(t).equals(targetName)) {
				dir = targetMap.get(t);
				break;
			}
		}
		while (tk.hasMoreTokens()) dir = dir.dirMap.get(tk.nextToken());
		return dir;
	}
	
	
	DirectoryObject GetTarget(int target) throws Exception {
		if (targetMap.containsKey(target))
			return targetMap.get(target);
		else
			return CreateTarget(target);
	}
	
	
	private DirectoryObject CreateTarget(int target) throws Exception {
		IEncryptedObject obj = rootObject.CreateChildObject();
		byte[] attr = new byte [8];
		IntAsBytes(ID_TARGET, attr, 0);
		IntAsBytes(target, attr, 4);
		obj.SetAttributeBlock(attr, 0, attr.length);
		DirectoryObject dir = new DirectoryObject(this, obj, target);
		targetMap.put(target, dir);
		return dir;
	}
}
