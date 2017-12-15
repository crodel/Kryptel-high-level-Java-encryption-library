/*******************************************************************************

  Product:       Kryptel/Java
  File:          DirectoryObject.java

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
import static com.kryptel.bslx.Conversions.*;
import static com.kryptel.bslx.Targets.*;
import static com.kryptel.storage.Kryptel.*;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.StringTokenizer;
import java.util.UUID;

import com.kryptel.ICompressionLevelCallback;
import com.kryptel.IProgressCallback;
import com.kryptel.IReplaceCallback;
import com.kryptel.Message;
import com.kryptel.Progress;
import com.kryptel.exceptions.UserAbortException;


class DirectoryObject extends AgentObject implements IEncryptedDirectory {

	DirectoryObject(Agent agent, IEncryptedObject object, int target) {
		super(agent, null, object);
		this.target = target;

		itemName = (target == TARGET_DEFAULT) ? File.separator : GetTargetName(target);
		timeStamp = 0;
	}
	
	
	DirectoryObject(Agent agent, DirectoryObject parent, IEncryptedObject object) throws Exception {
		super(agent, parent, object);
		FetchAttrBlock();
		target = TARGET_UNKNOWN;		// Ordinary folder, neither target nor root.
	}
	
	DirectoryObject(Agent agent, DirectoryObject parent, IEncryptedObject object, String name, long time) throws Exception {
		super(agent, parent, object);
		InitAttrBlock(name, time);
		target = TARGET_UNKNOWN;		// Ordinary folder, neither target nor root.
	}
	
	
	//
	// IFileSystemAttributes
	//
	
	
	public void SetName(String name) throws Exception {
		if (parent == null || target == TARGET_UNKNOWN) throw new Exception("DirectoryObject::SetName : Can't set root directory name.");
		if (IsDeleted()) throw new Exception("DirectoryObject::SetName : Can't modify deleted directory.");

		EnumChildren();
		if (parent.dirMap.containsKey(name) || parent.fileMap.containsKey(name)) throw new Exception("DirectoryObject::SetName : Duplicate name.");

		parent.RenameChildDir(itemName, name);
		itemName = name;
		SaveAttrBlock();
	}
	
	
	public long GetAttributes() throws Exception {
		long attr = EFFL_ITEM_IS_DIRECTORY;
		if (!dirMap.isEmpty()) attr |= EFFL_ITEM_CONTAINS_DIRECTORIES;
		if (!fileMap.isEmpty()) attr |= EFFL_ITEM_CONTAINS_FILES;
		if (parent != null && target != TARGET_UNKNOWN) { 
			if (itemDescription != null && !itemDescription.isEmpty()) attr |= EFFL_ITEM_HAS_DESCRIPTION;
			if (IsDeleted()) attr |= EFFL_ITEM_DELETED;
		}
		return attr;
	}
	
	
	public void SetAttributes(int attr) throws Exception {
		if (parent == null || target == TARGET_UNKNOWN) throw new Exception("DirectoryObject::SetAttributes : Can't set root directory attributes.");
		if (IsDeleted()) throw new Exception("DirectoryObject::SetAttributes : Can't modify deleted directory.");
		// Nothing to do - system-neutral implementation ignores system-specific attributes
	}
	
	
	//
	// IEncryptedDirectory
	//
	
	
	public IEncryptedDirectory[] GetDirectories() throws Exception {
		EnumChildren();
		
		ArrayList<IEncryptedDirectory> arr = new ArrayList<IEncryptedDirectory>(dirMap.size());
		for (DirectoryObject dir: dirMap.values()) {
			if (!dir.IsDeleted() || (agent.storageControlFlags & FSCF_ENUMS_RETURN_DELETED) != 0) arr.add(dir);
		}
		
		return arr.toArray(new IEncryptedDirectory [arr.size()]);
	}

	
	public IEncryptedDirectory GetDirectory(String uniquePath, boolean bCreate) throws Exception {
		if (uniquePath == null || uniquePath.isEmpty()) throw new Exception("DirectoryObject::GetDirectory : Missing or empty directory path.");
		
		StringTokenizer tk = new StringTokenizer(uniquePath, File.separator + "/\\");
		if (!tk.hasMoreTokens()) throw new Exception("DirectoryObject::GetDirectory : Missing or empty directory path.");
		
		EnumChildren();
		
		String name = tk.nextToken();
		DirectoryObject dir = dirMap.get(name);
		if (dir == null) {
			if (bCreate) {
				if (fileMap.containsKey(name)) throw new Exception(Message.Get(Message.Code.FolderConflictingName));
				if (IsDeleted()) throw new Exception("DirectoryObject::GetDirectory : Can't create subdirectory within deleted directory.");
				dir = new DirectoryObject(agent, this, storageObject.CreateChildObject(), name, System.currentTimeMillis() / 1000L);
				dirMap.put(name, dir);
			}
			else
				return null;
		}
		
		String path = null;
		while (tk.hasMoreTokens()) {
			if (path != null)
				path = path + File.separator + tk.nextToken();
			else
				path = tk.nextToken();
		}
		
		return (path != null) ? dir.GetDirectory(path, bCreate) : dir;
	}


	public IEncryptedFile[] GetFiles() throws Exception {
		EnumChildren();
		
		ArrayList<IEncryptedFile> arr = new ArrayList<IEncryptedFile>(fileMap.size());
		for (FileObject file: fileMap.values()) {
			if (!file.IsDeleted() || (agent.storageControlFlags & FSCF_ENUMS_RETURN_DELETED) != 0) arr.add(file);
		}
		
		return arr.toArray(new IEncryptedFile [arr.size()]);
	}

	
	public IEncryptedFile GetFile(String uniqueName, boolean bCreate) throws Exception {
		if (uniqueName == null || uniqueName.isEmpty()) throw new Exception("DirectoryObject::GetFile : Missing or empty file name.");
		
		EnumChildren();
		
		FileObject file = fileMap.get(uniqueName);
		if (file == null && bCreate) {
			if (IsDeleted()) throw new Exception("DirectoryObject::GetFile : Can't create file within deleted directory.");
			if (dirMap.containsKey(uniqueName)) throw new Exception(Message.Get(Message.Code.FileConflictingName));
			file = new FileObject(agent, this, storageObject.CreateChildObject(), uniqueName, System.currentTimeMillis() / 1000L, null, null);
			fileMap.put(uniqueName, file);
		}
		
		return file;
	}

	
	public void Move(String name, IEncryptedDirectory dest) throws Exception {
		if (GetItemPath(this).equals(GetItemPath(dest))) return;									// Moving to itself, nothing to do
		
		EnumChildren();
		if (!dirMap.containsKey(name) && !fileMap.containsKey(name)) return;			// No such item, nothing to do
		
		DirectoryObject destDir = agent.FindDirectoryObject(dest);
		if (destDir.IsDeleted()) throw new Exception("DirectoryObject::Move : Can't move object to deleted directory.");
		
		DirectoryObject dp = dirMap.get(name);
		if (dp != null && dp.IsDeleted()) throw new Exception("DirectoryObject::Move : Can't move deleted directory.");

		// If object with such name exists in the destination directory, delete it
		// However if both the objects are directories, then move contents recursively
		if (destDir.dirMap.containsKey(name)) {			// Subdirectory with such name exists in the destination directory
			if (dp != null) {			// Both the objects are directories, move children recursively
				destDir = destDir.dirMap.get(name);
				for (String dn: dp.dirMap.keySet()) dp.Move(dn, destDir);
				for (String fn: dp.fileMap.keySet()) dp.Move(fn, destDir);
				return;
			}
			else		// Moving file
				destDir.Delete(name, true);
		}
		else if (destDir.fileMap.containsKey(name))	// File with such name exists in the destination directory
			destDir.Delete(name, false);
		
		// Move the object
		if (dp != null) {			// Moving directory
			dirMap.remove(name);
			dp.storageObject.MoveTo(destDir.storageObject);
			dp.parent = destDir;
			destDir.dirMap.put(name, dp);
		}
		else {		// Moving file
			assert fileMap.containsKey(name);			// Sanity check
			FileObject fp = fileMap.get(name);
			if (fp.IsDeleted()) throw new Exception("DirectoryObject::Move : Can't move deleted file.");
			fileMap.remove(name);
			fp.storageObject.MoveTo(destDir.storageObject);
			fp.parent = destDir;
			destDir.fileMap.put(name, fp);
		}
	}

	
	public IFileSystemAttributes Delete(String name, boolean recursive) throws Exception {
		IEncryptedFileStorageInfo agentInfo = agent.GetFileStorageInfo();
		boolean bActualDeletion = (agentInfo.GetFileStorageCapabilities() & ESTOR_KEEPS_DELETED_OBJECTS) == 0;
		
		EnumChildren();
		
		if (fileMap.containsKey(name)) {
			FileObject file = fileMap.get(name);
			if (file.IsDeleted()) throw new Exception("DirectoryObject::Delete : Attempt to delete an already deleted file.");

			storageObject.DeleteChildObject(file.storageObject.GetObjectID());
			
			fileMap.remove(name);
			if (!bActualDeletion) {
				fileMap.put(file.GenerateUniqueName(), file);
				return file;
			}
			else
				return null;
		}
		
		else if (dirMap.containsKey(name)) {
			DirectoryObject dir = dirMap.get(name);
			if (dir.IsDeleted()) throw new Exception("DirectoryObject::Delete : Attempt to delete an already deleted directory.");
			if (!recursive && dir.storageObject.GetChildren() != null) throw new Exception("DirectoryObject::Delete : Directory is not empty - use recursice delete.");

			if (recursive) dir.DeleteChildren();
			storageObject.DeleteChildObject(dir.storageObject.GetObjectID());
			
			dirMap.remove(name);
			if (!bActualDeletion) {
				dirMap.put(dir.GenerateUniqueName(), dir);
				return dir;
			}
			else
				return null;
		}
		else
			throw new Exception("DirectoryObject::Delete : Object with specified name not found.");
	}

	
	public IFileSystemAttributes Undelete(String uniqueName, boolean recursive) throws Exception {
		IEncryptedFileStorageInfo agentInfo = agent.GetFileStorageInfo();
		if ((agentInfo.GetFileStorageCapabilities() & ESTOR_KEEPS_DELETED_OBJECTS) == 0) throw new Exception("DirectoryObject::Undelete : Storage does not support undelete operation.");
		
		EnumChildren();

		if (fileMap.containsKey(uniqueName)) {
			FileObject file = fileMap.get(uniqueName);
			if (!file.IsDeleted()) throw new Exception("DirectoryObject::Undelete : Attempt to undelete file that is not deleted.");

			storageObject.UndeleteChildObject(file.storageObject.GetObjectID(), true);		// recursive must be set to true to restore thumbnails and alternate streams
			fileMap.remove(uniqueName);
			
			String newName = GetVersionedName(file.itemName);
			if (newName != null) {
				file.itemName = newName;
				SaveAttrBlock();
			}
			fileMap.put(file.itemName, file);
			return (IFileSystemAttributes)file;
		}
		
		else if (dirMap.containsKey(uniqueName)) {
			DirectoryObject dir = dirMap.get(uniqueName);
			if (!dir.IsDeleted()) throw new Exception("DirectoryObject::Undelete : Attempt to undelete directory that is not deleted.");

			storageObject.UndeleteChildObject(dir.storageObject.GetObjectID(), false);
			fileMap.remove(uniqueName);
			
			String newName = GetVersionedName(dir.itemName);
			if (newName != null) {
				dir.itemName = newName;
				SaveAttrBlock();
			}
			dirMap.put(dir.itemName, dir);
			
			if (recursive) dir.UndeleteChildren();
			return (IFileSystemAttributes)dir;
		}
		else
			throw new Exception("DirectoryObject::Undelete : Object with specified name not found.");
	}
	
	
	public void Decrypt(String targetDir, Object arg, IReplaceCallback replaceCallback, IProgressCallback progressFunc) throws Exception {
		boolean bRestore = targetDir == null || targetDir.isEmpty();
		if (bRestore && !agent.IsBackupAgent()) throw new Exception("DirectoryObject::Decrypt : Empty target directory allowed for backups only.");
		
		String path;
		if (agent.IsBackupAgent()) {
			path = (parent != null) ? parent.GetTargetedPath() : GetTargetedPath();
			if (!bRestore)		// Target dir specified
					path = (targetDir.endsWith(File.separator) ? targetDir.substring(0, targetDir.length() - 1) : targetDir) + path;
		}
		else		// File agent
			path = targetDir.endsWith(File.separator) ? targetDir : targetDir + File.separator;
		
		DecryptTo(path, arg, replaceCallback, (progressFunc != null) ? (new Progress(progressFunc, arg, GetTotalStoredSize())) : null);
	}

	
	public void StartEncryptionBatch() throws Exception {
		if (IsDeleted()) throw new Exception("DirectoryObject::StartEncryptionBatch : Can't modify deleted directory.");
		if (bEncrBatchValid) throw new Exception("DirectoryObject::StartEncryptionBatch : Another batch is still active.");
		assert encrBatch.isEmpty();
		EnumChildren();
		bEncrBatchValid = true;
	}

	
	public void AddToEncryptionBatch(String path) throws Exception {
		if (!bEncrBatchValid) throw new Exception("DirectoryObject::AddToEncryptionBatch : Batch is not valid, use StartEncryptionBatch.");
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
				for (String path: batch) totalSize += GetFileObjectSize(new File(path));
				progress = new Progress(progressFunc, arg, totalSize);
			}
		}
		
		// Encrypt all items in the batch
		
		for (String path: batch) {
			File f = new File(path);
			String name = f.getName();
			
			if (f.isDirectory()) {
				DirectoryObject dir = dirMap.get(name);
				if (dir == null) {
					dir = new DirectoryObject(agent, this, storageObject.CreateChildObject(), name, f.lastModified() / 1000L);
					dirMap.put(name, dir);
				}
				else
					dir.EnumChildren();
				dir.EncryptFrom(path, arg, replaceCallback, progress, comprLevel);
			}
			
			else if (f.isFile())
				EncryptFile(f, arg, replaceCallback, progress, comprLevel);
		}
		
		encrBatch.clear();
		bEncrBatchValid = false;
	}
	
	
	public void StartDecryptionBatch(String targetDir) throws Exception {
		if (bDecrBatchValid) throw new Exception("DirectoryObject::StartDecryptionBatch : Another batch is still active.");
		assert decrFiles.isEmpty() && decrDirs.isEmpty();

		boolean bRestore = targetDir == null || targetDir.isEmpty();
		if (bRestore && !agent.IsBackupAgent()) throw new Exception("DirectoryObject::StartDecryptionBatch : Empty target directory allowed for backups only.");
		
		if (bRestore)
			decrTargetDir = parent.GetTargetedPath();
		else
			decrTargetDir = targetDir.endsWith(File.separator) ? targetDir : targetDir + File.separator;

		EnumChildren();
		bDecrBatchValid = true;
	}
	
	
	public void AddToDecryptionBatch(String uniquePath) throws Exception {
		if (!bDecrBatchValid) throw new Exception("DirectoryObject::AddToDecryptionBatch : Batch is not valid, use StartDecryptionBatch.");

		String[] elems = uniquePath.split("\\/");
		
		DirectoryObject dir = this;
		if (elems.length > 1) {
			for (int i = 0; i < elems.length - 1; i++) {
				dir = dirMap.get(elems[i]);
				if (dir == null) throw new Exception("DirectoryObject::AddToDecryptionBatch : Specified subdirectory does not exist.");
				dir.EnumChildren();
			}
		}
		
		String objName = elems[elems.length - 1];
		if (dir.dirMap.containsKey(objName)) {
			DirectoryObject d = dir.dirMap.get(objName);
			d.EnumChildren();
			decrDirs.add(d);
		}
		else if (dir.fileMap.containsKey(objName))
			decrFiles.add(dir.fileMap.get(objName));
		else
			throw new Exception("DirectoryObject::AddToDecryptionBatch : Item's unique name not found.");
	}
	
	
	public void DecryptBatch(Object arg, IReplaceCallback replaceCallback, IProgressCallback progressFunc) throws Exception {
		if (!bDecrBatchValid) throw new Exception("DirectoryObject::DecryptBatch : Batch is not valid, use StartDecryptionBatch.");
		if (decrDirs.isEmpty() && decrFiles.isEmpty()) {
			bDecrBatchValid = false;
			return;
		}
		
		DirectoryObject[] dirBatch = decrDirs.toArray(new DirectoryObject [decrDirs.size()]);
		FileObject[] fileBatch = decrFiles.toArray(new FileObject [decrFiles.size()]);
		
		Progress progress = null;
		if (progressFunc != null) {
			if (!decrDirs.isEmpty() || decrFiles.size() > 1) {
				long totalSize = 0;
				if (!decrDirs.isEmpty()) for (DirectoryObject di: dirBatch) totalSize += di.GetTotalStoredSize();
				if (!decrFiles.isEmpty()) for (FileObject fi: fileBatch) totalSize += fi.FileSize();
				progress = new Progress(progressFunc, arg, totalSize);
			}
			else
				progress = new Progress(progressFunc, arg);
		}
		
		// Decrypt directories

		if (!decrDirs.isEmpty()) {
			for (DirectoryObject di: dirBatch)
				di.DecryptTo(decrTargetDir, arg, replaceCallback, progress);
		}
		
		// Decrypt files
		
		if (!decrFiles.isEmpty()) {
			for (FileObject fi: fileBatch) {
				String fname = fi.IsDeleted() ? (fi.itemName + FILE_DELETED_SUFFIX) : fi.itemName;
				fi.DecryptTo(decrTargetDir, fname, arg, replaceCallback, progress);
			}
		}
	}

	
  //
  // Private data and methods
  //

	
	int target;
	
	HashMap<String, DirectoryObject> dirMap = null;
	HashMap<String, FileObject> fileMap = null;
	
	// Batch encryption
	private boolean bEncrBatchValid = false;
	private ArrayList<String> encrBatch = new ArrayList<String>();

	// Batch decryption
	private String decrTargetDir;
	private boolean bDecrBatchValid = false;
	private ArrayList<DirectoryObject> decrDirs = new ArrayList<DirectoryObject>();
	private ArrayList<FileObject> decrFiles = new ArrayList<FileObject>();

	
	//
	// Local functions
	//
	
	
	protected void FetchAttrBlock() throws Exception {
		if (bAttrLoaded) return;
		
		byte[] attrBlock = storageObject.GetAttributeBlock();
		if (attrBlock.length < 20) throw new Exception("DirectoryObject::FetchAttrBlock : Invalid size of directory attribute block.");
		
		assert GetAsInt(attrBlock, 0) == ID_DIRECTORY;
		timeStamp = GetAsLong(attrBlock, 8);
		
		int len, pos = 16;
		len = GetAsShort(attrBlock, pos) * 2; pos += 2;
		itemName =  new String(attrBlock, pos, len, "UnicodeLittleUnmarked"); pos += len;
		len = GetAsShort(attrBlock, pos) * 2; pos += 2;
		itemDescription =  new String(attrBlock, pos, len, "UnicodeLittleUnmarked"); pos += len;
		
		bAttrLoaded = true;
	}
	
	
	protected void SaveAttrBlock() throws Exception {
		assert bAttrLoaded;
		
		byte[] byteName = itemName.getBytes("UnicodeLittleUnmarked");
		int nameLen = byteName.length / 2;

		byte[] byteDescription = null;
		int descrLen = 0;
		if (itemDescription != null) {
			byteDescription = itemDescription.getBytes("UnicodeLittleUnmarked");
			descrLen = byteDescription.length / 2;
		}

		int attrLen = 2 * 4 + 8 + 2 + nameLen * 2 + 2 + descrLen * 2;
		
		byte[] attrBlock = new byte [attrLen];
		IntAsBytes(ID_DIRECTORY, attrBlock, 0);
		attrBlock[4] = SYSTEM_NEUTRAL;
		attrBlock[5] = attrBlock[6] = attrBlock[7] = 0;
		LongAsBytes(timeStamp, attrBlock, 8);
		ShortAsBytes((short)nameLen, attrBlock, 16);
		System.arraycopy(byteName, 0, attrBlock, 18, nameLen * 2);
		ShortAsBytes((short)descrLen, attrBlock, 18 + nameLen * 2);
		if (itemDescription != null) System.arraycopy(byteDescription, 0, attrBlock, 20 + nameLen * 2, descrLen * 2);
		
		storageObject.SetAttributeBlock(attrBlock, 0, attrLen);
	}
	
	
	private void RenameChildDir(String oldName, String newName) {
		// EnumChildren call is not required here as this function is called by a child (that is, EnumChildren has already been called)
		DirectoryObject d = dirMap.get(oldName);
		assert d != null;
		dirMap.remove(oldName);
		dirMap.put(newName, d);
	}
	
	
	void RenameChildFile(String oldName, String newName) {
		// EnumChildren call is not required here as this function is called by a child (that is, EnumChildren has already been called)
		FileObject fo = fileMap.get(oldName);
		assert fo != null;
		fileMap.remove(oldName);
		fileMap.put(newName, fo);
	}
	
	
	void EnumChildren() throws Exception {
		if (dirMap != null) return;
		dirMap = new HashMap<String, DirectoryObject>();
		fileMap = new HashMap<String, FileObject>();
		
		IEncryptedObject obj;
		DirectoryObject dir;
		FileObject file;
		
		UUID[] children = storageObject.GetChildren();
		if (children == null) return;
		
		for(UUID id: children) {
			obj = storageObject.GetChildObject(id);
			if (IsDirectory(obj)) {
				dir = new DirectoryObject(agent, this, obj);
				dirMap.put(dir.GetUniqueName(), dir);
			}
			else {		// File
				file = new FileObject(agent, this, obj);
				fileMap.put(file.GetUniqueName(), file);
			}
		}
	}


	private void DeleteChildren() throws Exception {
		EnumChildren();

		if (fileMap.size() != 0) {
			// Duplicate file map to iterate through unmodified names
			ArrayList<String> names = new ArrayList<String>(fileMap.size());
			for (String nm: fileMap.keySet()) names.add(nm);
			
			for (int i = 0; i < names.size(); i++) Delete(names.get(i), true);		// 2nd arg is ignored for files
		}
		
		if (dirMap.size() != 0) {
			// Duplicate directory map to iterate through unmodified names
			ArrayList<String> names = new ArrayList<String>(dirMap.size());
			for (String nm: dirMap.keySet()) names.add(nm);
			
			for (int i = 0; i < names.size(); i++) Delete(names.get(i), true);		// 2nd arg is true as function is called as part of recursive delete
		}
	}


	private void UndeleteChildren() throws Exception {
		EnumChildren();

		if (fileMap.size() != 0) {
			// Duplicate file map to iterate through unmodified names
			ArrayList<String> names = new ArrayList<String>(fileMap.size());
			for (String nm: fileMap.keySet()) names.add(nm);
			
			for (int i = 0; i < names.size(); i++) Undelete(names.get(i), true);		// 2nd arg is ignored for files
		}
		
		if (dirMap.size() != 0) {
			// Duplicate directory map to iterate through unmodified names
			ArrayList<String> names = new ArrayList<String>(dirMap.size());
			for (String nm: dirMap.keySet()) names.add(nm);
			
			for (int i = 0; i < names.size(); i++) Undelete(names.get(i), true);		// 2nd arg is true as function is called as part of recursive undelete
		}
	}


	// Returns null if the name is unique; returns versioned name if not
	private String GetVersionedName(String name) {
		String versionedName = name;
		int ver = 1;
		
		while (dirMap.containsKey(versionedName) || fileMap.containsKey(versionedName)) versionedName = name + String.format(" (%d)", ++ver);
		return (ver > 1) ? versionedName : null;
	}
	
	
	private String GetTargetedPath() throws Exception {
		if (parent == null)
			return GetTargetPath(target);
		else
			return parent.GetTargetedPath() + itemName + File.separator;
	}
	
	
	String GetRecoveryPath() {
		if (parent == null)
			return (target != TARGET_DEFAULT) ? (GetTargetName(target) + File.separator) : "";
		else
			return parent.GetRecoveryPath() + itemName + File.separator;
	}
	
	
	String GetReplacementPath() {
		if (parent == null)
			return "";
		else
			return parent.GetRecoveryPath() + itemName + File.separator;
	}
	
	
	long GetTotalStoredSize() throws Exception {
		EnumChildren();

		long fsize = 0;
		for (DirectoryObject dir: dirMap.values()) fsize += dir.GetTotalStoredSize();
		for (FileObject file: fileMap.values()) fsize += file.FileSize();
		return fsize;
	}
	
	
	static long GetFileObjectSize(File f) {
		if (f.isDirectory()) {
			long size = 0;
			File[] fa = f.listFiles();
			for (File fi: fa) size += GetFileObjectSize(fi);
			return size;
		}
		else if (f.isFile())
			return f.length();
		else		// Neither file nor directory
			return 0;
	}
	
	
	void EncryptFrom(String srcPath, Object arg, IReplaceCallback replaceCallback, Progress progress, ICompressionLevelCallback comprLevel) throws Exception {
		File dirf = new File(srcPath);
		File[] chlist = dirf.listFiles();

		EnumChildren();
		
		for (File ch: chlist) {
			if (ch.isDirectory()) {
				String name = ch.getName();
				if (fileMap.containsKey(name)) throw new Exception(Message.Get(Message.Code.FolderConflictingName));
				DirectoryObject dir = dirMap.get(name);
				if (dir == null) {
					dir = new DirectoryObject(agent, this, storageObject.CreateChildObject(), name, ch.lastModified() / 1000L);
					dirMap.put(name, dir);
				}
				else
					dir.EnumChildren();
				dir.EncryptFrom(ch.getPath(), arg, replaceCallback, progress, comprLevel);
			}
			
			else if (ch.isFile())
				EncryptFile(ch, arg, replaceCallback, progress, comprLevel);
		}
	}
	
	
	void EncryptFile(File f, Object arg, IReplaceCallback replaceCallback, Progress progress, ICompressionLevelCallback comprLevel) throws Exception {
		String name = f.getName();
		if (dirMap.containsKey(name)) throw new Exception(Message.Get(Message.Code.FileConflictingName));
		long tmNew = f.lastModified() / 1000L;
		FileObject file = fileMap.get(name);
		
		String oldDescription = null;
		HashSet<String> oldKeywords = null;

		if (file != null) {		// Such file exists, use replaceCallback
			IEncryptedFileStorageInfo agentInfo = agent.GetFileStorageInfo();
			IReplaceCallback.REPLACE_ACTION ra;
			
			if (replaceCallback != null) {
				StringBuilder newName = new StringBuilder(name);
				do {
					ra = replaceCallback.Callback(arg, newName, f.length(), tmNew, GetReplacementPath() + file.itemName, file.FileSize(), file.timeStamp);
					if (ra == IReplaceCallback.REPLACE_ACTION.RENAME) {
						name = newName.toString().trim();
						if (dirMap.containsKey(name)) throw new Exception(Message.Get(Message.Code.FileConflictingName));
						file = fileMap.get(name);
					}
				} while (ra == IReplaceCallback.REPLACE_ACTION.RENAME && file != null);
			}
			else {
				ra = IReplaceCallback.DEFAULT_REPLACE_ACTION;
				if (ra == IReplaceCallback.REPLACE_ACTION.RENAME) ra = IReplaceCallback.REPLACE_ACTION.VERSION;
			}
			
			if (ra == IReplaceCallback.REPLACE_ACTION.VERSION) {
				int ver = 1;
				String nnm;
				do {
					nnm = name + String.format(" (%d)", ++ver);
				} while (dirMap.containsKey(nnm) || fileMap.containsKey(nnm));
				name = nnm;
			}
			
			switch (ra) {
				case REPLACE:
					if ((agent.storageControlFlags & FSCF_PERSISTANT_DESCRIPTIONS) != 0) oldDescription = file.itemDescription;
					if ((agent.storageControlFlags & FSCF_PERSISTANT_KEYWORDS) != 0) oldKeywords = file.keywords;
					storageObject.DeleteChildObject(file.storageObject.GetObjectID());
					fileMap.remove(name);
					if ((agentInfo.GetFileStorageCapabilities() & ESTOR_KEEPS_DELETED_OBJECTS) != 0) fileMap.put(file.GenerateUniqueName(), file);
					break;
					
				case ABORT:
					throw new UserAbortException();
					
				case SKIP:
					return;
					
				default:
					break;
			}
		}
		
		assert !dirMap.containsKey(name) && !fileMap.containsKey(name);

		file = new FileObject(agent, this, storageObject.CreateChildObject(), name, tmNew, oldDescription, oldKeywords);
		try {
			file.EncryptFrom(f, progress, comprLevel);
		}
		catch (Exception e) {
			storageObject.DeleteChildObject(file.storageObject.GetObjectID());
			throw e;
		}
		fileMap.put(name, file);
	}
	
	
	void DecryptTo(String targetDir, Object arg, IReplaceCallback replaceCallback, Progress progress) throws Exception {
		String target;
		if (parent != null) {
			target = targetDir + itemName;
			File dirf = new File(target);
			dirf.mkdirs();
			target += File.separator;
		}
		else
			target = targetDir;
		
		EnumChildren();
		
		boolean bSkipDeleted = (agent.storageControlFlags & FSCF_WILDCARDS_DECRYPT_DELETED) == 0;
		
		for (DirectoryObject dir: dirMap.values()) {
			if (bSkipDeleted && dir.IsDeleted()) continue;
			dir.DecryptTo(target, arg, replaceCallback, progress);
		}
		
		String fname;
		for (FileObject file: fileMap.values()) {
			if (file.IsDeleted()) {
				if (bSkipDeleted) continue;
				fname = file.itemName + FILE_DELETED_SUFFIX;
			}
			else
				fname = file.itemName;
			file.DecryptTo(target, fname, arg, replaceCallback, progress);
		}
	}
	
	
	void FillStatisticsBlock(FileStorageStatistics stat) throws Exception {
		EnumChildren();
		
		long attr;
		
		for (DirectoryObject dir: dirMap.values()) {
			attr = dir.GetAttributes();
			if ((attr & EFFL_ITEM_DELETED) != 0)
				stat.nDeletedFolders++;
			else
				stat.nFolders++;
			if ((attr & EFFL_ITEM_HAS_DESCRIPTION) != 0) stat.nItemsWithDescriptions++;
			
			dir.FillStatisticsBlock(stat);
		}
		
		for (FileObject file: fileMap.values()) {
			attr = file.GetAttributes();

			if ((attr & EFFL_ITEM_DELETED) != 0)
				stat.nDeletedFiles++;
			else
				stat.nFiles++;

			if ((attr & EFFL_ITEM_HAS_DESCRIPTION) != 0) stat.nItemsWithDescriptions++;
			if ((attr & EFFL_ITEM_HAS_KEYWORDS) != 0) stat.nItemsWithKeywords++;
			if ((attr & EFFL_ITEM_HAS_THUMBNAILS) != 0) stat.nItemsWithThumbnails++;
		}
	}
}
