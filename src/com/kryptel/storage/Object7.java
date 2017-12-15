/*******************************************************************************

  Product:       Kryptel/Java
  File:          Object7.java

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
import static com.kryptel.storage.Kryptel.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.UUID;

import com.kryptel.Message;


final class Object7 implements IEncryptedObject {
	Object7(Storage7 storage, Object7 parent, Object7 next) {
		this.storage = storage;
		this.parent = parent;
		this.next = next;
		
		if (parent == null) objectID = NULL_GUID;

		initVector = new byte [storage.cipherParamBlock.cipherBlockSize];
	}

	
	public UUID GetObjectID() {
		return objectID;
	}

	
	public IEncryptedObject GetParent() {
		return parent;
	}


	public int GetObjectFlags() {
		int fl = 0;
		if (attrBlock != null) fl |= EFL_ATTRIBUTE_BLOCK;
		if (dataSize > 0) fl |= EFL_DATA_STREAM;
		if (child != null) fl |= EFL_CHILD_OBJECTS;
		if (bStreamIsOpen) fl |= EFL_STREAM_BUSY;
		if (IsDeleted()) fl |= EFL_OBJECT_DELETED;
		return fl;
	}


	public byte[] GetAttributeBlock() {
		return attrBlock;
	}


	public void SetAttributeBlock(byte[] attr, int start, int size) throws Exception {
		if (storage.IsReadOnly()) throw new Exception("Object::SetAttributeBlock : Requested operation is illegal for a read-only container.");
		if (IsDeleted()) throw new Exception("Object::SetAttributeBlock : Attempt to modify a deleted object.");
		if (attrBlock != null) {
			storage.statistics.nAttributeBlocks--;
			storage.statistics.uTotalAttributeSize -= attrBlock.length;
		}

		if (attr != null && size > 0) {
			attrBlock = Arrays.copyOfRange(attr, start, start + size);

			storage.statistics.nAttributeBlocks++;
			storage.statistics.uTotalAttributeSize += size;
		}
		else
			attrBlock = null;
		
		storage.SetModified();
		
		if (!storage.IsNewFileActive()) new FixupAttachAttributes(storage, this);
	}


	public boolean StreamExists() {
		return dataSize != 0;
	}


	public long StreamSize() {
		return StreamExists() ? dataUncomprSize : 0;
	}


	public IEncryptedStream CreateStream(byte comprLevel) throws Exception {
		return CreateStream(null, comprLevel);
	}


	public IEncryptedStream CreateStream(byte[] recData, byte comprLevel) throws Exception {
		if (storage.IsReadOnly()) throw new Exception("Object::CreateStream : Requested operation is illegal for a read-only container.");
		if (IsDeleted()) throw new Exception("Object::CreateStream : Attempt to modify a deleted object.");
		if (StreamExists()) throw new Exception("Object::CreateStream : Stream already exists.");

		if (storage.bStreamActive) throw new Exception("Object::CreateStream : Can't perform the requested operation while there is an active stream.");
			
		bStreamInNewFile = storage.IsNewFileActive();
		
		Stream7 stream = null;
		try {
			storage.SetModified();		// We need to call this first to setup segment 'in-progress' header

			if (recData != null && recData.length > 0) {
				if (recData.length > MAX_RECOVERY_DATA_SIZE) throw new Exception("Object::CreateStream : Recovery data is too large.");
				this.recData = recData;
				int bs = storage.cipherParamBlock.cipherBlockSize;
				recBlockSize = (short)((16 + bs + 16 + 2 + recData.length + 4 + (bs - 1)) / bs);
				recBlockSize *= (short)bs;
			}
			
			storage.bStreamActive = true;
			bStreamIsOpen = true;
			
			dataPos = storage.nextDataPos;
			dataSize = 0;
			dataUncomprSize = 0;
			
			storage.rand.nextBytes(initVector);
			
			if (bStreamInNewFile)
				storage.newFile.seek(storage.nextDataPos);
			else
				storage.contFile.seek(storage.nextDataPos);
			
			stream = new Stream7(this, false, comprLevel);
		}
		catch (Exception e) {
			assert stream == null;			// We haven't created a stream
			storage.bStreamActive = false;
			throw e;
		}
		
		return stream;
	}


	public IEncryptedStream OpenStream() throws Exception {
		if (!StreamExists()) throw new Exception("Object::OpenStream : Stream does not exist.");

			if (storage.bStreamActive) throw new Exception("Object::OpenStream : Can't preform the requested operation while there is an active stream.");

			Stream7 stream = null;
			try {
				storage.bStreamActive = true;
				bStreamIsOpen = true;
				
				stream = new Stream7(this, true, CT_DEFAULT_COMPRESSION);
			}
			catch (Exception e) {
				assert stream == null;			// The stream is not open
				storage.bStreamActive = false;
				throw e;
			}

		return stream;
	}


	public void DeleteStream() throws Exception {
		if (storage.IsReadOnly()) throw new Exception("Object::DeleteStream : Requested operation is illegal for a read-only container.");
		if (IsDeleted()) throw new Exception("Object::DeleteStream : Attempt to modify a deleted object.");

		if (storage.bStreamActive) throw new Exception("Object::DeleteStream : Can't perform the requested operation while there is an active stream.");

		if (StreamExists()) {
			
			// Fix statistics
			
			if (dataSize > 0) {
				storage.statistics.nStreams--;
				storage.statistics.uDataAreaUsed -= dataSize;
				storage.statistics.uTotalStreamSize -= dataUncomprSize;
				storage.statistics.uDataAreaUnused += dataSize;
			
				if (recBlockSize > 0) {
					storage.statistics.nRecoveryBlocks--;
					storage.statistics.uTotalRecoveryBlockSize -= recBlockSize;
					storage.statistics.uDataAreaUnused += recBlockSize;
				}
				
				storage.CheckIfCompressionNeeded();
			}
		
			// Delete stream
			
			dataSize = 0;
			dataUncomprSize = 0;
			
			if (recData != null) {
				recData = null;
				recBlockSize = 0;
			}
			storage.SetModified();

			if (!storage.IsNewFileActive()) new FixupAttachData(storage, this);
		}
	}


	public void MoveTo(IEncryptedObject newParent) throws Exception {
		if (storage.IsReadOnly()) throw new Exception("Object::MoveTo : Requested operation is illegal for a read-only container.");
		if (IsDeleted()) throw new Exception("Object::MoveTo : Attempt to modify a deleted object.");
		if (parent == null) throw new Exception("Object::MoveTo : Can' move the root object.");

		// As the first step we need to translate newParent to the object pointer
		// (instead of IEncryptedObject) as we need to access its private fields.
		
		Object7 newParentObject = (Object7)newParent;
		
		// At this point newParentObject points to the Object of newParent
	
		FixupMoveObject fixupObject = storage.IsNewFileActive() ? null : new FixupMoveObject(storage, this);

		// Check if ID is unique and generate new if not
		Object7 ch;
		boolean bUnique;

		byte[] uidb = new byte [16];
		for (;;) {
			// Check if ID is unique
			ch = newParentObject.child;
			bUnique = true;
			while (ch != null) {
				if (ch.objectID.equals(objectID)) {
					bUnique = false;
					break;
				}
				ch = ch.next;
			}
			if (bUnique) break;
			storage.rand.nextBytes(uidb);
			objectID = UuidFromBytes(uidb, 0);
		}
		
		// Remove itself from the parent's children list
		ch = parent.child;
		if (!ch.objectID.equals(objectID)) {		// Not the first child
			for (;;) {
				assert ch.next != null;
				if (ch.next.objectID.equals(objectID)) break;		// Found self
				ch = ch.next;
			}
			// pChild points to our predecessor in the children list
			assert ch.next.next == next;		// Sanity check
			ch.next = next;		// Remove itself;
		}
		else		// The first child
			parent.child = next;
		
		// Insert itself into the new parent's children list
		next = newParentObject.child;
		newParentObject.child = this;
		parent = newParentObject;
		
		if (fixupObject != null) fixupObject.SetTarget(this);

		storage.SetModified();
	}


	public UUID[] GetChildren() throws Exception {
		ArrayList<UUID> chlist = new ArrayList<UUID>();
		Object7 ch = child;
		while (ch != null) {
			chlist.add(ch.objectID);
			ch = ch.next;
		}
		return (chlist.size() != 0) ? chlist.toArray(new UUID [chlist.size()]) : null;
	}


	public IEncryptedObject CreateChildObject() throws Exception {
		if (storage.IsReadOnly()) throw new Exception("Object::CreateChildObject : Requested operation is illegal for a read-only container.");
		if (IsDeleted()) throw new Exception("Object::CreateChildObject : Attempt to modify a deleted object.");
		
		// Generate an unique object ID
		Object7 ch;
		boolean bUnique;
		byte[] uidb = new byte [16];
		UUID id;

		do {
			storage.rand.nextBytes(uidb);
			id = UuidFromBytes(uidb, 0);
			// Check if ID is unique
			ch = child;
			bUnique = true;
			while (ch != null) {
				if (ch.objectID.equals(id)) {
					bUnique = false;
					break;
				}
				ch = ch.next;
			}
		} while (!bUnique);
		
		child = new Object7(storage, this, child);
		child.objectID = id;
		
		storage.statistics.nObjects++;

		if (!storage.IsNewFileActive()) new FixupAddObject(storage, child);
		
		storage.SetModified();

		return child;
	}


	public IEncryptedObject GetChildObject(UUID id) {
		Object7 ch = child;
		while (ch != null && !ch.objectID.equals(id)) ch = ch.next;
		return (ch != null) ? ch : null;
	}


	public void DeleteChildObject(UUID id) throws Exception {
		if (storage.IsReadOnly()) throw new Exception("Object::DeleteChildObject : Requested operation is illegal for a read-only container.");
		if (IsDeleted()) throw new Exception("Object::DeleteChildObject : Attempt to modify a deleted object.");

		if (storage.bStreamActive) throw new Exception("Object::DeleteChildObject : Can't perform the requested operation while there is an active stream.");

		Object7 ch = child;
		while (ch != null && !ch.objectID.equals(id)) ch = ch.next;
		if (ch == null) throw new Exception("Object::DeleteChildObject : Attempt to delete a non-existent object.");

		if (ch.IsDeleted()) throw new Exception("Object::DeleteChildObject : Attempt to delete a deleted object.");
		ch.MarkAsDeleted();
		if (!storage.IsNewFileActive()) new FixupDeleteObject(storage, ch);
		storage.SetModified();
	}


	public void UndeleteChildObject(UUID id, boolean recursive) throws Exception {
		if (storage.IsReadOnly()) throw new Exception("Object::UndeleteChildObject : Requested operation is illegal for a read-only container.");
		if (!IsDeleted()) throw new Exception("Object::DeleteChildObject : Attempt to modify a deleted object.");

		if (storage.bStreamActive) throw new Exception("Object::UndeleteChildObject : Can't perform the requested operation while there is an active stream.");

		Object7 ch = child;
		while (ch != null && !ch.objectID.equals(id)) ch = ch.next;
		if (ch == null) throw new Exception("Object::UndeleteChildObject : Attempt to undelete a non-existent object.");

		if (!ch.IsDeleted()) throw new Exception("Object::UndeleteChildObject : Attempt to undelete an object, which is not deleted.");
		ch.UnmarkAsDeleted(recursive);
		if (!storage.IsNewFileActive()) new FixupUndeleteObject(storage, ch, recursive);
		storage.SetModified();
	}

	
	//
	// Private data
	//
	
	private static final int MAX_RECOVERY_DATA_SIZE				= 8 * 1024;
	
	UUID objectID;
	
	Storage7 storage;
	Object7 parent;
	private Object7 next;
	private Object7 child;
	
	long dataPos;
	long dataSize;
	long dataUncomprSize;
	
	short recBlockSize;
	byte[] recData;
	
	byte[] initVector;
	byte[] dataHash;
	
	byte[] attrBlock;
	
	private boolean bDeleted = false;
	boolean bStreamIsOpen = false;
	boolean bStreamInNewFile = false;
	
	
	//
	// Private methods
	//
	
	
	boolean IsDeleted() { return bDeleted; }
	
	
	void LoadObject() throws Exception {
		// Load own record
		LoadSelf();

		// Load children
		
		short tag;
		for (;;) {
			if (storage.dirBuffer.Size() < 2) throw new Exception(Message.Get(Message.Code.InvalidContainer));
			tag = GetAsShort(storage.dirBuffer.Retrieve(2), 0);
			
			if (tag == OBJECT_END) break;
			if (tag != OBJECT_START) throw new Exception(Message.Get(Message.Code.InvalidContainer));
			
			child = new Object7(storage, this, child);
			child.LoadObject();
		}
	}
	
	
	private void LoadSelf() throws Exception {
		if (storage.dirBuffer.Size() < 22) throw new Exception(Message.Get(Message.Code.InvalidContainer));
		objectID = UuidFromBytes(storage.dirBuffer.Retrieve(16), 0);
		
		// Load stream data
		assert dataSize == 0;				// Assert new object
		LoadStream();
		
		// Load attribute block
		assert attrBlock == null;		// Assert new object
		LoadAttributes();
	}
	
	
	void LoadStream() throws Exception {

		// If replacing stream, fix statistics

		if (dataSize > 0) {
			storage.statistics.nStreams--;
			storage.statistics.uDataAreaUsed -= dataSize;
			storage.statistics.uTotalStreamSize -= dataSize;
			
			if (recBlockSize != 0) {
				storage.statistics.nRecoveryBlocks--;
				storage.statistics.uTotalRecoveryBlockSize -= recBlockSize;
			}
		}
		
		// Load new stream

		byte[] b = new byte [8];
		storage.dirBuffer.Retrieve(b, 0, 6);
		dataSize = GetAsLong(b, 0) & 0x0000FFFFFFFFFFFFL;
		
		if (dataSize != 0) {
			if (storage.dirBuffer.Size() < (30 + storage.cipherParamBlock.cipherBlockSize)) throw new Exception(Message.Get(Message.Code.InvalidContainer));
			storage.dirBuffer.Retrieve(b, 0, 6);
			dataUncomprSize = GetAsLong(b, 0) & 0x0000FFFFFFFFFFFFL;
			storage.dirBuffer.Retrieve(b, 0, 6);
			dataPos = GetAsLong(b, 0) & 0x0000FFFFFFFFFFFFL;
			recBlockSize = GetAsShort(storage.dirBuffer.Retrieve(2), 0);
			initVector = storage.dirBuffer.Retrieve(storage.cipherParamBlock.cipherBlockSize);
			dataHash = storage.dirBuffer.Retrieve(16);

			// Update statistics

			storage.statistics.nStreams++;
			storage.statistics.uDataAreaUsed += dataSize;
			storage.statistics.uTotalStreamSize += dataSize;
			
			if (recBlockSize > 0) {
				storage.statistics.nRecoveryBlocks++;
				storage.statistics.uTotalRecoveryBlockSize += recBlockSize;
			}
		}
	}
	
	
	void LoadAttributes() throws Exception {

		// If replacing attribute block, fix statistics

		if (attrBlock != null) {
			Arrays.fill(attrBlock, (byte)0);
			storage.statistics.nAttributeBlocks--;
			storage.statistics.uTotalAttributeSize -= attrBlock.length;
		}
		
		// Load attributes
		
		if (storage.dirBuffer.Size() < 4) throw new Exception(Message.Get(Message.Code.InvalidContainer));
		int len = GetAsInt(storage.dirBuffer.Retrieve(4), 0);
		
		if (len != 0) {
			if (storage.dirBuffer.Size() < len) throw new Exception(Message.Get(Message.Code.InvalidContainer));
			attrBlock = storage.dirBuffer.Retrieve(len);

			// Update statistics
			
			storage.statistics.nAttributeBlocks++;
			storage.statistics.uTotalAttributeSize += attrBlock.length;
		}
		else
			attrBlock = null;
	}
	
	
	Object7 LocateChild(UUID[] uidPath, int start, int nGuids) {
		// NOTE: The path must lead to an existing child
		if (nGuids == 0) return this;

		Object7 ch = child;
		while (!ch.objectID.equals(uidPath[start])) {
			ch = ch.next;
			assert ch != null;
		}
		
		return ch.LocateChild(uidPath, start + 1, nGuids - 1);
	}
	
	
	void LoadChildFromFixup(short tag) throws Exception {
		child = new Object7(storage, this, child);
		
		storage.statistics.nObjects++;
		
		if (tag == FIXUP_RECORD_CREATE_OBJECT) {
			child.objectID = UuidFromBytes(storage.dirBuffer.Retrieve(16), 0);
		}
		else {		// Non-empty object
			assert tag == FIXUP_RECORD_ADD_OBJECT;
			child.LoadSelf();
		}
	}


	void MoveMe(Object7 target) {
		assert !IsDeleted();

		// Remove itself from the parent's children list
		Object7 ch = parent.child;
		if (ch.objectID != objectID) {		// Not the first child
			for (;;) {
				assert ch.next != null;
				if (ch.next.objectID == objectID) break;		// Found self
				ch = ch.next;
			}
			// ch points to our predecessor in the children list
			assert ch.next.next == next;		// Sanity check
			ch.next = next;		// Remove itself;
		}
		else		// The first child
			parent.child = next;
		
		// Insert itself into the new parent's children list
		next = target.child;
		target.child = this;
		parent = target;

		objectID = UuidFromBytes(storage.dirBuffer.Retrieve(16), 0);
	}


	void MarkAsDeleted() throws Exception {
		assert !IsDeleted();
		
		Object7 ch = child;
		while (ch != null) {
			if (!ch.IsDeleted()) ch.MarkAsDeleted();
			ch = ch.next;
		}

		bDeleted = true;

		// Update statistics
		
		storage.statistics.nObjects--;
		storage.statistics.nDeletedObjects++;

		if (attrBlock != null) {
			storage.statistics.nAttributeBlocks--;
			storage.statistics.uTotalAttributeSize -= attrBlock.length;
		}
		
		if (dataSize > 0) {
			storage.statistics.nStreams--;
			storage.statistics.uDataAreaUsed -= dataSize;
			storage.statistics.uTotalStreamSize -= dataUncomprSize;
			storage.statistics.uDataAreaUnused += dataSize;
			
			if (recBlockSize > 0) {
				storage.statistics.nRecoveryBlocks--;
				storage.statistics.uTotalRecoveryBlockSize -= recBlockSize;
				storage.statistics.uDataAreaUnused += recBlockSize;
			}
					
			storage.CheckIfCompressionNeeded();
		}
	}


	void UnmarkAsDeleted(boolean recursive) {
		assert IsDeleted();

		if (recursive) {
			Object7 ch = child;
			while (ch != null) {
				ch.UnmarkAsDeleted(recursive);
				ch = ch.next;
			}
		}

		bDeleted = false;

		// Update statistics
		
		storage.statistics.nObjects++;
		storage.statistics.nDeletedObjects--;

		if (attrBlock != null) {
			storage.statistics.nAttributeBlocks++;
			storage.statistics.uTotalAttributeSize += attrBlock.length;
		}
		
		if (dataSize > 0) {
			storage.statistics.nStreams++;
			storage.statistics.uDataAreaUsed += dataSize;
			storage.statistics.uTotalStreamSize += dataUncomprSize;
			storage.statistics.uDataAreaUnused -= dataSize;
			
			if (recBlockSize > 0) {
				storage.statistics.nRecoveryBlocks++;
				storage.statistics.uTotalRecoveryBlockSize += recBlockSize;
				storage.statistics.uDataAreaUnused -= recBlockSize;
			}
		}
	}


	void StoreObject() throws Exception {
		if (IsDeleted()) return;
		
		byte[] buf = new byte [58 + storage.cipherParamBlock.cipherBlockSize];
		
		ShortAsBytes(OBJECT_START, buf, 0);
		UuidToBytes(buf, 2, objectID);
		
		LongAsBytes(dataSize, buf, 18);
		int pos = 24;
		
		if (dataSize > 0) {
			LongAsBytes(dataUncomprSize, buf, pos); pos += 6;
			LongAsBytes(dataPos, buf, pos); pos += 6;
			
			ShortAsBytes(recBlockSize, buf, pos); pos += 2;
			System.arraycopy(initVector, 0, buf, pos, storage.cipherParamBlock.cipherBlockSize); pos += storage.cipherParamBlock.cipherBlockSize;
			System.arraycopy(dataHash, 0, buf, pos, 16); pos += 16;
		}
		
		IntAsBytes((attrBlock != null) ? attrBlock.length : 0, buf, pos); pos += 4;
		
		storage.hmacFunc.Hash(buf, 0, pos);
		storage.compressor.Compress(buf, 0, pos);
		if (attrBlock != null && attrBlock.length != 0) {
			storage.hmacFunc.Hash(attrBlock, 0, attrBlock.length);
			storage.compressor.Compress(attrBlock, 0, attrBlock.length);
		}
		
		Object7 ch = child;
		while (ch != null) {
			ch.StoreObject();
			ch = ch.next;
		}

		ShortAsBytes(OBJECT_END, buf, 0);
		storage.hmacFunc.Hash(buf, 0, 2);
		storage.compressor.Compress(buf, 0, 2);
	}


	void MoveDataStreams() throws IOException {
		if (bDeleted) return;
		
		Object7 ch = child;
		while (ch != null) {
			ch.MoveDataStreams();
			ch = ch.next;
		}
		
		if (bStreamInNewFile) return;
		
		if (dataSize > 0) {
			long uSize = dataSize + recBlockSize;
			storage.contFile.seek(dataPos);
			storage.newFile.seek(storage.nextDataPos);
			dataPos = storage.nextDataPos;
			storage.nextDataPos += uSize;
			
			int len;
			while (uSize > 0) {
				len = (int)Math.min(uSize, storage.ioBuffer.length);
				storage.contFile.read(storage.ioBuffer, 0, len);
				storage.newFile.write(storage.ioBuffer, 0, len);
				storage.newMD5.update(storage.ioBuffer, 0, len);
				uSize -= len;
			}
		}
	}
}
