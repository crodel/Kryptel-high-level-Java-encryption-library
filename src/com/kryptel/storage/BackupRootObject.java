/*******************************************************************************

  Product:       Kryptel/Java
  File:          BackupRootObject.java

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


import static com.kryptel.bslx.Targets.*;

import java.io.File;
import java.util.ArrayList;
import java.util.StringTokenizer;

import com.kryptel.ICompressionLevelCallback;
import com.kryptel.IProgressCallback;
import com.kryptel.IReplaceCallback;
import com.kryptel.Progress;
import com.kryptel.bslx.Targets.TargetedPath;


public class BackupRootObject implements IEncryptedDirectory {

	BackupRootObject(BackupAgent agent) {
		this.agent = agent;
	}
	
	
	//
	// IFileSystemAttributes
	//

	
	public IEncryptedDirectory GetParent() throws Exception {
		return null;
	}


	public String GetUniqueName() throws Exception {
		throw new Exception("BackupRoot::GetUniqueName : Unsupported operation.");
	}


	public String GetName() throws Exception {
		throw new Exception("BackupRoot::GetName : Unsupported operation.");
	}


	public void SetName(String name) throws Exception {
		throw new Exception("BackupRoot::SetName : Unsupported operation.");
	}


	public long GetTime() throws Exception {
		throw new Exception("BackupRoot::GetTime : Unsupported operation.");
	}


	public void SetTime(long ftime) throws Exception {
		throw new Exception("BackupRoot::SetTime : Unsupported operation.");
	}


	public String GetDescription() throws Exception {
		throw new Exception("BackupRoot::GetDescription : Unsupported operation.");
	}


	public void SetDescription(String descr) throws Exception {
		throw new Exception("BackupRoot::SetDescription : Unsupported operation.");
	}


	public long GetAttributes() throws Exception {
		throw new Exception("BackupRoot::GetAttributes : Unsupported operation.");
	}


	public void SetAttributes(int attr) throws Exception {
		throw new Exception("BackupRoot::SetAttributes : Unsupported operation.");
	}
	
	
	//
	// IEncryptedDirectory
	//


	public IEncryptedDirectory[] GetDirectories() throws Exception {
		throw new Exception("BackupRoot::GetDirectories : Unsupported operation.");
	}


	public IEncryptedDirectory GetDirectory(String uniquePath, boolean bCreate) throws Exception {
		throw new Exception("BackupRoot::GetDirectory : Unsupported operation.");
	}


	public IEncryptedFile[] GetFiles() throws Exception {
		throw new Exception("BackupRoot::GetFiles : Unsupported operation.");
	}


	public IEncryptedFile GetFile(String uniqueName, boolean bCreate) throws Exception {
		throw new Exception("BackupRoot::GetFile : Unsupported operation.");
	}


	public void Move(String name, IEncryptedDirectory dest) throws Exception {
		throw new Exception("BackupRoot::Move : Unsupported operation.");
	}


	public IFileSystemAttributes Delete(String name, boolean recursive) throws Exception {
		throw new Exception("BackupRoot::Delete : Unsupported operation.");
	}


	public IFileSystemAttributes Undelete(String uniqueName, boolean recursive) throws Exception {
		throw new Exception("BackupRoot::Undelete : Unsupported operation.");
	}


	public void Decrypt(String targetDir, Object arg, IReplaceCallback replaceCallback, IProgressCallback progressFunc) throws Exception {
		Progress progress = null;
		if (progressFunc != null) {
			long totalSize = 0;
			for (DirectoryObject d: agent.targetMap.values()) totalSize += d.GetTotalStoredSize();
			progress = new Progress(progressFunc, arg, totalSize);
		}
		
		boolean bAltDir = targetDir != null && !targetDir.isEmpty();
		String path;
		for (DirectoryObject d: agent.targetMap.values()) {
			path = GetTargetPath(d.target);
			if (bAltDir)		// Target dir specified
					path = (targetDir.endsWith(File.separator) ? targetDir.substring(0, targetDir.length() - 1) : targetDir) + path;
			
			d.DecryptTo(path, arg, replaceCallback, progress);
		}
	}


	public void StartEncryptionBatch() throws Exception {
		if (bEncrBatchValid) throw new Exception("BackupRoot::StartEncryptionBatch : Another batch is still active.");
		assert encrBatch.isEmpty();
		bEncrBatchValid = true;
	}


	public void AddToEncryptionBatch(String path) throws Exception {
		if (!bEncrBatchValid) throw new Exception("BackupRoot::AddToEncryptionBatch : Batch is not valid, use StartEncryptionBatch.");
		encrBatch.add(path);
	}


	public void EncryptBatch(Object arg, IReplaceCallback replaceCallback, IProgressCallback progressFunc, ICompressionLevelCallback comprLevel) throws Exception {
		if (!bEncrBatchValid) throw new Exception("DirectoryObject::EncryptBatch : Batch is not valid, use StartEncryptionBatch.");
		if (encrBatch.isEmpty()) {
			bEncrBatchValid = false;
			return;
		}
		
		String[] batch = encrBatch.toArray(new String [encrBatch.size()]);
		
		Progress progress = null;
		if (progressFunc != null) {
			boolean bSingleFile = false;
			if (batch.length == 1) {
				File f = new File(batch[0]);
				bSingleFile = f.isFile();
			}
			
			if (bSingleFile)
				progress = new Progress(progressFunc, arg);
			else {
				long totalSize = 0;
				for (String path: batch) totalSize += DirectoryObject.GetFileObjectSize(new File(path));
				progress = new Progress(progressFunc, arg, totalSize);
			}
		}
		
		// Encrypt all items in the batch
		
		for (String path: batch) {
			TargetedPath tp = RecognizeTarget(path);
			DirectoryObject dir = agent.GetTarget(tp.target);
			StringTokenizer tk = new StringTokenizer(tp.path, File.separator + "/\\");
			StringBuilder sb = new StringBuilder();
			while (tk.countTokens() > 1) {
				sb.append(File.separator);
				sb.append(tk.nextToken());
			}
			String dirPath = sb.substring(1);
			dir = (DirectoryObject)dir.GetDirectory(dirPath, true);
			
			File f = new File(path);
			
			if (f.isDirectory())
				dir.EncryptFrom(path, arg, replaceCallback, progress, comprLevel);
			
			else if (f.isFile())
				dir.EncryptFile(f, arg, replaceCallback, progress, comprLevel);
		}
		
		encrBatch.clear();
		bEncrBatchValid = false;
	}


	public void StartDecryptionBatch(String targetDir) throws Exception {
		throw new Exception("BackupRoot::StartDecryptionBatch : Unsupported operation.");
	}


	public void AddToDecryptionBatch(String uniquePath) throws Exception {
		throw new Exception("BackupRoot::AddToDecryptionBatch : Unsupported operation.");
	}


	public void DecryptBatch(Object arg, IReplaceCallback replaceCallback, IProgressCallback progressFunc) throws Exception {
		throw new Exception("BackupRoot::DecryptBatch : Unsupported operation.");
	}
	
	
  //
  // Private data and methods
  //

	
	private BackupAgent agent;
	
	// Batch encryption
	private boolean bEncrBatchValid = false;
	private ArrayList<String> encrBatch = new ArrayList<String>();
}
