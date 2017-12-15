/*******************************************************************************

  Product:       Kryptel/Java
  File:          FileObject.java

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
import static com.kryptel.storage.Kryptel.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;

import com.kryptel.ICompressionLevelCallback;
import com.kryptel.IReplaceCallback;
import com.kryptel.Message;
import com.kryptel.Progress;
import com.kryptel.exceptions.UserAbortException;


class FileObject extends AgentObject implements IEncryptedFile {

	FileObject(Agent agent, DirectoryObject parent, IEncryptedObject object) throws Exception {
		super(agent, parent, object);
		FetchAttrBlock();
	}

	FileObject(Agent agent, DirectoryObject parent, IEncryptedObject object, String name, long time, String descr, HashSet<String> kwd) throws Exception {
		super(agent, parent, object);
		InitAttrBlock(name, time, descr, kwd);
	}
	
	//
	// IFileSystemAttributes
	//
	
	
	public void SetName(String name) throws Exception {
		if (IsDeleted()) throw new Exception("FileObject::SetName : Can't modify deleted file.");

		if (parent.dirMap.containsKey(name) || parent.fileMap.containsKey(name)) throw new Exception("FileObject::SetName : Duplicate name.");

		parent.RenameChildFile(itemName, name);
		itemName = name;
		SaveAttrBlock();
	}
	
	
	public long GetAttributes() throws Exception {
		long attr = 0;
		if (itemDescription != null && !itemDescription.isEmpty()) attr |= EFFL_ITEM_HAS_DESCRIPTION;
		if (!keywords.isEmpty()) attr |= EFFL_ITEM_HAS_KEYWORDS;
		if (IsDeleted()) attr |= EFFL_ITEM_DELETED;
		return attr;
	}
	
	
	public void SetAttributes(int attr) throws Exception {
		if (IsDeleted()) throw new Exception("FileObject::SetAttributes : Can't modify deleted file.");
		// Nothing to do - system-neutral implementation ignores system-specific attributes
	}
	
	
	//
	// IEncryptedFile
	//


	public long FileSize() throws Exception {
		return bSparse ? fileSize : storageObject.StreamSize();
	}


	public IEncryptedStream Create(byte uComprLevel) throws Exception {
		if (IsDeleted()) throw new Exception("FileObject::Create : Can't modify deleted file.");
		
		String path = parent.GetRecoveryPath() + itemName;
		if (storageObject.StreamExists()) storageObject.DeleteStream();
		
		bSparse = false;
		fileSize = 0;
		
		return storageObject.CreateStream(path.getBytes("UnicodeLittleUnmarked"), uComprLevel);
	}


	public IEncryptedStream Open() throws Exception {
		if (bSparse)
			return (fileSize > 0) ? (new SparseStream(storageObject.OpenStream())) : (new ZeroStream());
		else
			return storageObject.StreamExists() ? storageObject.OpenStream() : (new ZeroStream());
	}


	public String[] GetKeywords() throws Exception {
		if (keywords.isEmpty()) return null;
		
		String[] kwd = new String [keywords.size()];
		int k = 0;

		Iterator<String> iter = keywords.iterator();
		while (iter.hasNext()) kwd[k++] = iter.next();
		return kwd;
	}


	public void SetKeywords(String[] kwd) throws Exception {
		keywords.clear();
		if (kwd != null && kwd.length > 0) {
			for (int i = 0; i < kwd.length; i++) keywords.add(kwd[i]);
		}
		SaveAttrBlock();
	}

	
	//
  // Private data
  //

	
	private static class RangeRecord {
		final long start;
		final long size;
		
		RangeRecord(long start, long size) {
			this.start = start;
			this.size = size;
		}
	}
	
	
	private long fileSize = 0;
	private boolean bSparse = false;
	private RangeRecord[] ranges;
	
	HashSet<String> keywords = new HashSet<String>();

	
	//
  // Private methods
  //
	
	
	protected void InitAttrBlock(String name, long time, String descr, HashSet<String> kwd) throws Exception {
		bSparse = false;
		itemDescription = descr;
		if (kwd != null) keywords = kwd;
		super.InitAttrBlock(name, time);
	}

	
	protected void FetchAttrBlock() throws Exception {
		if (bAttrLoaded) return;
		
		byte[] attrBlock = storageObject.GetAttributeBlock();
		if (attrBlock.length < 24) throw new Exception("FileObject::FetchAttrBlock : Invalid size of file attribute block.");
		
		assert GetAsInt(attrBlock, 0) == ID_FILE;
		timeStamp = GetAsLong(attrBlock, 8);
		
		int nRecs = GetAsInt(attrBlock, 16);
		int len, pos = 20;
		if (nRecs != -1) {
			bSparse = true;
			fileSize = GetAsLong(attrBlock, pos);
			pos += 8;
			
			long start, size;
			ranges = new RangeRecord [nRecs];
			
			for (int i = 0; i < nRecs; i++) {
				start = GetAsLong(attrBlock, pos);
				pos += 8;
				size = GetAsLong(attrBlock, pos);
				pos += 8;
				ranges[i] = new RangeRecord(start, size);
			}
		}

		len = GetAsShort(attrBlock, pos) * 2; pos += 2;
		itemName =  new String(attrBlock, pos, len, "UnicodeLittleUnmarked"); pos += len;
		
		len = GetAsShort(attrBlock, pos) * 2; pos += 2;
		itemDescription =  new String(attrBlock, pos, len, "UnicodeLittleUnmarked"); pos += len;
		
		len = GetAsShort(attrBlock, pos) * 2; pos += 2;
		String kwd =  new String(attrBlock, pos, len, "UnicodeLittleUnmarked"); pos += len;
		String[] arrKwd = kwd.split(",");
		keywords.clear();
		for (int i = 0; i < arrKwd.length; i++) keywords.add(arrKwd[i]);
		
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
		
		byte[] byteKeywords = null;
		int kwdLen = 0;
		if (!keywords.isEmpty()) {
			StringBuilder sb = new StringBuilder();
			Iterator<String> iter = keywords.iterator();
			sb.append(iter.next().trim());
			while (iter.hasNext()) sb.append("," + iter.next().trim());
			byteKeywords = sb.toString().getBytes("UnicodeLittleUnmarked");
			kwdLen = byteKeywords.length / 2;
		}

		int attrLen = 2 * 4 + 8 + 4 + 2 + nameLen * 2 + 2 + descrLen * 2 + 2 + kwdLen * 2;
		
		if (bSparse) attrLen += 8 + ranges.length * (8 + 8);	// Although we don't support sparseness when storing files, we need to save existing sparse file's attribute block correctly in case it is modified
		
		byte[] attrBlock = new byte [attrLen];
		IntAsBytes(ID_FILE, attrBlock, 0);
		attrBlock[4] = SYSTEM_NEUTRAL;
		attrBlock[5] = attrBlock[6] = attrBlock[7] = 0;
		LongAsBytes(timeStamp, attrBlock, 8);
		IntAsBytes(bSparse ? ranges.length : -1, attrBlock, 16);
		
		int pos =  20;
		
		if (bSparse) {
			LongAsBytes(fileSize, attrBlock, pos); pos += 8;
			for (int i = 0; i < ranges.length; i++) {
				LongAsBytes(ranges[i].start, attrBlock, pos); pos += 8;
				LongAsBytes(ranges[i].size, attrBlock, pos); pos += 8;
			}
		}

		ShortAsBytes((short)nameLen, attrBlock, pos); pos += 2;
		System.arraycopy(byteName, 0, attrBlock, pos, nameLen * 2); pos += nameLen * 2;

		ShortAsBytes((short)descrLen, attrBlock, pos); pos += 2;
		if (itemDescription != null) {
			System.arraycopy(byteDescription, 0, attrBlock, pos, descrLen * 2);
			pos += descrLen * 2;
		}

		ShortAsBytes((short)kwdLen, attrBlock, pos); pos += 2;
		if (kwdLen != 0) {
			System.arraycopy(byteKeywords, 0, attrBlock, pos, kwdLen * 2);
			//pos += kwdLen * 2;		// Uncomment if storing more fields
		}
		
		storageObject.SetAttributeBlock(attrBlock, 0, attrLen);
	}
	
	
	void EncryptFrom(File f, Progress progress, ICompressionLevelCallback comprLevel) throws Exception {
		String path = f.getPath();
		long fSize = f.length();
		byte compr = (comprLevel != null) ? comprLevel.Get(path) : DEFAULT_COMPRESSION_LEVEL;

		if (progress != null) progress.NewFile(path, fSize);
		
		int len;
		
		try (IEncryptedStream stream = Create(compr);
				 FileInputStream fin = new FileInputStream(f)) {
			while (fSize > 0) {
				len = (int)Math.min(fSize, agent.ioBuffer.length);
				fin.read(agent.ioBuffer, 0, len);
				stream.Write(agent.ioBuffer, 0, len);
				if (progress != null) progress.Step(len);
				fSize -= len;
			}
		}
		finally {
			if (progress != null) progress.Discard();
		}
}
	
	
	void DecryptTo(String targetDir, String altName, Object arg, IReplaceCallback replaceCallback, Progress progress) throws Exception {
		String name = (altName != null) ? altName : itemName;
		String targetPath = targetDir + name;
		File f = new File(targetPath);
		if (f.exists()) {
			if (f.isDirectory()) throw new Exception(Message.Get(Message.Code.FileConflictingName));
			
			IReplaceCallback.REPLACE_ACTION ra;
			if (replaceCallback != null) {
				StringBuilder newName = new StringBuilder(name);
				do {
					ra = replaceCallback.Callback(arg, newName, FileSize(), timeStamp, targetPath, f.length(), f.lastModified() / 1000L);
					if (ra == IReplaceCallback.REPLACE_ACTION.RENAME) {
						name = newName.toString().trim();
						targetPath = targetDir + name;
						f = new File(targetPath);
						if (!f.exists())
							ra = IReplaceCallback.REPLACE_ACTION.REPLACE;		// Not actual replace as the file does not exist
						else if (f.isDirectory())
							throw new Exception(Message.Get(Message.Code.FileConflictingName));
					}
				} while (ra == IReplaceCallback.REPLACE_ACTION.RENAME);
			}
			else {
				ra = IReplaceCallback.DEFAULT_REPLACE_ACTION;
				if (ra == IReplaceCallback.REPLACE_ACTION.RENAME) ra = IReplaceCallback.REPLACE_ACTION.VERSION;
			}
			
			switch (ra) {
				case VERSION:
					int ver = 1;
					String nnm;
					do {
						nnm = name + String.format(" (%d)", ++ver);
						targetPath = targetDir + nnm;
						f = new File(targetPath);
					} while (f.exists());
					name = nnm;
					break;

				case REPLACE:
					f.delete();
					break;

				case SKIP:
					return;
					
				case ABORT:
					throw new UserAbortException();

				default:
					break;
			}
		}
			
		long fSize = FileSize();
		
		if (progress != null) progress.NewFile(targetPath, fSize);
		
		int len;
		try (IEncryptedStream stream = Open();
				 FileOutputStream fout = new FileOutputStream(f)) {
			while (fSize > 0) {
				len = (int)Math.min(fSize, agent.ioBuffer.length);
				stream.Read(agent.ioBuffer, 0, len);
				fout.write(agent.ioBuffer, 0, len);
				if (progress != null) progress.Step(len);
				fSize -= len;
			}
		}
		finally {
			if (progress != null) progress.Discard();
		}
	}
	
	
	//
	// Special streams
	//
	
	
	private class SparseStream implements IEncryptedStream {
		
		private SparseStream(IEncryptedStream baseStream) {
			this.baseStream = baseStream;
		}


		public void Read(byte[] buf, int start, int size) throws Exception {
			int len, k;
			
			// Find the correspondent segment

			for (k = 0; k < ranges.length; k++) {
				if (streamPos < ranges[k].start || streamPos < (ranges[k].start + ranges[k].size)) break;
			}

			// Main loop
			
			while (size > 0) {
				if (k == ranges.length) {		// Trailing zeros
					Arrays.fill(buf, start, start + size, (byte)0);
					streamPos += size;
					return;
				}
				
				else if (streamPos < ranges[k].start) {		// Zero area
					len = (int)Math.min(size, (ranges[k].start - streamPos));
					Arrays.fill(buf, start, start + len, (byte)0);
					start += len;
					size -= len;
					streamPos += len;
				}
				
				else {			// Must be data area
					assert streamPos < (ranges[k].start + ranges[k].size);
					len = (int)Math.min(size, (ranges[k].start + ranges[k].size - streamPos));
					baseStream.Read(buf, start, len);
					start += len;
					size -= len;
					streamPos += len;
					k++;		// Now we should use the next segment (unless we are done, in that case the value of k is not important)
				}
			}
		}


		public void Write(byte[] buf, int start, int size) throws Exception {
			throw new Exception("SparseStream::Write : Attempt to write to read-only stream.");
		}


		public long Size() {
			return fileSize;
		}


		public void Seek(long newPos) throws Exception {
			throw new Exception("SparseStream::Seek : Unsupported operation.");
		}


		public void SeekEof() throws Exception {
			throw new Exception("SparseStream::SeekEof : Unsupported operation.");
		}


		public long Pos() {
			return streamPos;
		}


		public boolean Eof() {
			return streamPos == fileSize;
		}


		public void SetEof() throws Exception {
			throw new Exception("SparseStream::SetEof : Unsupported operation.");
		}


		public void Close() throws Exception {
			baseStream.Close();
		}


		public void close() throws Exception {
			Close();
		}

		
		//
		// Stream private data
		//
		
		private IEncryptedStream baseStream;
		private long streamPos = 0;
	}
	
	
	private class ZeroStream implements IEncryptedStream {

		public void Read(byte[] buf, int start, int size) throws Exception {
		}


		public void Write(byte[] buf, int start, int size) throws Exception {
			throw new Exception("ZeroStream::Write : Attempt to write to read-only stream.");
		}


		public long Size() {
			return 0;
		}


		public void Seek(long newPos) throws Exception {
			throw new Exception("ZeroStream::Seek : Unsupported operation.");
		}


		public void SeekEof() throws Exception {
			throw new Exception("ZeroStream::SeekEof : Unsupported operation.");
		}


		public long Pos() {
			return 0;
		}


		public boolean Eof() {
			return true;
		}


		public void SetEof() throws Exception {
			throw new Exception("ZeroStream::SetEof : Unsupported operation.");
		}


		public void Close() throws Exception {
		}


		public void close() throws Exception {
			Close();
		}
	}
}
