/*******************************************************************************

  Product:       Kryptel/Java
  File:          FixupObject7.java

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


import static com.kryptel.bslx.Conversions.*;
import static com.kryptel.storage.Kryptel.*;

import java.util.Arrays;
import java.util.UUID;


abstract class FixupObject7 {
	FixupObject7(Storage7 stor, Object7 obj, short tg) {
		tag = tg;
		storage = stor;
		next = null;
		
		nUids = 0;
		Object7 ob = obj;
		do {
			nUids++;
			ob = ob.parent;
		} while (ob.parent != null);		// We don't store root's ID
		
		uidPath = new UUID [nUids];
		ob = obj;
		for (int i = nUids - 1; i >= 0; i--) {
			uidPath[i] = ob.objectID;
			ob = ob.parent;
		}

		// Insert self to end of fixup list
		if (storage.fixupList != null) {
			assert storage.fixupListTail != null;
			storage.fixupListTail.next = this;
		}
		else {
			assert storage.fixupListTail == null;
			storage.fixupList = this;
		}
		storage.fixupListTail = this;
	}
	
	
	FixupObject7 Reduce() {			// Returns pointer to the next object to reduce
		return next;
	}
	
	
	abstract void Store() throws Exception;


	void StorePath() throws Exception {
		// Store tag
		byte[] b = ShortAsBytes(tag);
		storage.hmacFunc.Hash(b, 0, 2);
		storage.compressor.Compress(b, 0, 2);
	
		// Store path
		b = IntAsBytes(nUids);
		storage.hmacFunc.Hash(b, 0, 2);
		storage.compressor.Compress(b, 0, 2);

		for (int i = 0; i < nUids; i++) {
			b = UuidToBytes(uidPath[i]);
			storage.hmacFunc.Hash(b, 0, 16);
			storage.compressor.Compress(b, 0, 16);
		}
	}
	
	
	boolean IsSameObject(FixupObject7 fo) {
		if (fo.nUids != nUids) return false;
		for (int i = 0; i < nUids; i++) {
			if (!uidPath[i].equals(fo.uidPath[i])) return false;
		}
		return true;
	}
	
	
	FixupObject7 RemoveObject(FixupObject7 prev, FixupObject7 current) {
		prev.next = current.next;
		if (prev.next == null) storage.fixupListTail = prev;
		return prev.next;
	}


	void DeleteMe() {
		if (storage.fixupList != this) {		// If I am not the first element
			FixupObject7 prev = storage.fixupList;
			while (prev.next != this) prev = prev.next;
			prev.next = next;

			if (next == null) {	// Am I the last element?
				assert storage.fixupListTail == this;
				storage.fixupListTail = prev;
			}
		}
		else {		// I am the first element
			storage.fixupList = next;
			if (next == null) {	// Am I also the last element?
				assert storage.fixupListTail == this;
				storage.fixupListTail = null;
			}
		}
	}
	
	
	//
	// Data
	//
	
	short tag;
	FixupObject7 next;
	
	protected Storage7 storage;
	protected UUID[] uidPath;
	protected int nUids;
}


//**************************************************************
//*** FixupAddObject


class FixupAddObject extends FixupObject7 {

	FixupAddObject(Storage7 stor, Object7 obj) {
		super(stor, obj, FIXUP_RECORD_ADD_OBJECT);

		recBlockSize = obj.recBlockSize;
		dataPos = obj.dataPos;
		dataSize = obj.dataSize;
		dataUncomprSize = obj.dataUncomprSize;
		
		if (dataSize > 0) {
			initVector = Arrays.copyOf(obj.initVector, obj.initVector.length);
			dataHash = Arrays.copyOf(obj.dataHash, obj.dataHash.length);
		}
		
		if (obj.attrBlock != null && obj.attrBlock.length != 0)
			attrBlock = Arrays.copyOf(obj.attrBlock, obj.attrBlock.length);
	}

	
	FixupObject7 Reduce() {
		FixupObject7 prev = this;
		FixupObject7 p = next;
		
		while (p != null) {
			if (IsSameObject(p)) {
				if (p.tag == FIXUP_RECORD_ATTACH_ATTRIBUTES) {		// Reduce
					attrBlock = ((FixupAttachAttributes)p).attrBlock;
					p = RemoveObject(prev, p);
					continue;
				}
				
				else if (p.tag == FIXUP_RECORD_ATTACH_DATA) {			// Reduce
					recBlockSize = ((FixupAttachData)p).recBlockSize;
					dataPos = ((FixupAttachData)p).dataPos;
					dataSize = ((FixupAttachData)p).dataSize;
					dataUncomprSize = ((FixupAttachData)p).dataUncomprSize;

					initVector = ((FixupAttachData)p).initVector;
					dataHash = ((FixupAttachData)p).dataHash;
					
					p = RemoveObject(prev, p);
					continue;
				}
			}
			prev = p;
			p = p.next;
		}
		
		return next;
	}


	void Store() throws Exception {
		boolean bFullObject = dataSize > 0 || attrBlock != null;

		tag = bFullObject ? FIXUP_RECORD_ADD_OBJECT : FIXUP_RECORD_CREATE_OBJECT;
		StorePath();

		if (bFullObject) {
			byte[] buf = new byte [40 + storage.cipherParamBlock.cipherBlockSize];

			LongAsBytes(dataSize, buf, 0);
			int pos = 6;
			
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
		}
	}
	
	
	//
	// Data
	//
	
	long dataPos;
	long dataSize;
	long dataUncomprSize;
	short recBlockSize;
	
	byte[] initVector;
	byte[] dataHash;

	byte[] attrBlock;
}


//**************************************************************
//*** FixupAttachAttributes


class FixupAttachAttributes extends FixupObject7 {

	FixupAttachAttributes(Storage7 stor, Object7 obj) {
		super(stor, obj, FIXUP_RECORD_ATTACH_ATTRIBUTES);

		if (obj.attrBlock != null && obj.attrBlock.length != 0)
			attrBlock = Arrays.copyOf(obj.attrBlock, obj.attrBlock.length);
	}


	FixupObject7 Reduce() {
		FixupObject7 prev = this;
		FixupObject7 p = next;
		
		while (p != null) {
			if (IsSameObject(p)) {
				if (p.tag == FIXUP_RECORD_ATTACH_ATTRIBUTES) {		// Reduce
					attrBlock = ((FixupAttachAttributes)p).attrBlock;
					p = RemoveObject(prev, p);
					continue;
				}
			}
			prev = p;
			p = p.next;
		}
		
		return next;
	}
	
	
	void Store() throws Exception {
		StorePath();
	
		if (attrBlock != null && attrBlock.length != 0) {
			byte[] blen = IntAsBytes(attrBlock.length);
			storage.hmacFunc.Hash(blen, 0, 4);
			storage.compressor.Compress(blen, 0, 4);
			
			storage.hmacFunc.Hash(attrBlock, 0, attrBlock.length);
			storage.compressor.Compress(attrBlock, 0, attrBlock.length);
		}
		else {
			byte[] blen = new byte [4];
			Arrays.fill(blen, (byte)0);
			storage.hmacFunc.Hash(blen, 0, 4);
			storage.compressor.Compress(blen, 0, 4);
		}
	}
	
	
	//
	// Data
	//
	
	byte[] attrBlock;
}


//**************************************************************
//*** FixupAttachData


class FixupAttachData extends FixupObject7 {

	FixupAttachData(Storage7 stor, Object7 obj) {
		super(stor, obj, FIXUP_RECORD_ATTACH_DATA);

		recBlockSize = obj.recBlockSize;
		dataPos = obj.dataPos;
		dataSize = obj.dataSize;
		dataUncomprSize = obj.dataUncomprSize;
		
		if (dataSize > 0) {
			initVector = Arrays.copyOf(obj.initVector, obj.initVector.length);
			dataHash = Arrays.copyOf(obj.dataHash, obj.dataHash.length);
		}
	}

	
	FixupObject7 Reduce() {
		FixupObject7 prev = this;
		FixupObject7 p = next;
		
		while (p != null) {
			if (IsSameObject(p)) {
				if (p.tag == FIXUP_RECORD_ATTACH_DATA) {			// Reduce
					recBlockSize = ((FixupAttachData)p).recBlockSize;
					dataPos = ((FixupAttachData)p).dataPos;
					dataSize = ((FixupAttachData)p).dataSize;
					dataUncomprSize = ((FixupAttachData)p).dataUncomprSize;

					initVector = ((FixupAttachData)p).initVector;
					dataHash = ((FixupAttachData)p).dataHash;
					
					p = RemoveObject(prev, p);
					continue;
				}
			}
			prev = p;
			p = p.next;
		}
		
		return next;
	}


	void Store() throws Exception {
		StorePath();

		byte[] buf = new byte [36 + storage.cipherParamBlock.cipherBlockSize];

		LongAsBytes(dataSize, buf, 0);
		int pos = 6;
		
		if (dataSize > 0) {
			LongAsBytes(dataUncomprSize, buf, pos); pos += 6;
			LongAsBytes(dataPos, buf, pos); pos += 6;
			
			ShortAsBytes(recBlockSize, buf, pos); pos += 2;
			System.arraycopy(initVector, 0, buf, pos, storage.cipherParamBlock.cipherBlockSize); pos += storage.cipherParamBlock.cipherBlockSize;
			System.arraycopy(dataHash, 0, buf, pos, 16); pos += 16;
		}

		storage.hmacFunc.Hash(buf, 0, pos);
		storage.compressor.Compress(buf, 0, pos);
	}
	
	
	//
	// Data
	//
	
	long dataPos;
	long dataSize;
	long dataUncomprSize;
	short recBlockSize;
	
	byte[] initVector;
	byte[] dataHash;
}


//**************************************************************
//*** FixupMoveObject


class FixupMoveObject extends FixupObject7 {

	FixupMoveObject(Storage7 stor, Object7 obj) {
		super(stor, obj, FIXUP_RECORD_MOVE_OBJECT);
	}


	void SetTarget(Object7 obj) {
		nTargetUids = 0;
		Object7 ob = obj;
		do {
			nTargetUids++;
			ob = ob.parent;
		} while (ob.parent != null);		// We don't store root's ID
		
		uidTargetPath = new UUID [nTargetUids];
		ob = obj;
		for (int i = nTargetUids - 1; i >= 0; i--) {
			uidTargetPath[i] = ob.objectID;
			ob = ob.parent;
		}
	}
	
	
	void Store() throws Exception {
		assert uidTargetPath !=null;
		
		StorePath();

		byte[] b = IntAsBytes(nTargetUids);
		storage.hmacFunc.Hash(b, 0, 2);
		storage.compressor.Compress(b, 0, 2);

		for (int i = 0; i < nTargetUids; i++) {
			b = UuidToBytes(uidTargetPath[i]);
			storage.hmacFunc.Hash(b, 0, 16);
			storage.compressor.Compress(b, 0, 16);
		}
	}
	
	
	//
	// Data
	//
	
	protected UUID[] uidTargetPath;
	protected int nTargetUids;
}


//**************************************************************
//*** FixupDeleteObject


class FixupDeleteObject extends FixupObject7 {

	FixupDeleteObject(Storage7 stor, Object7 obj) {
		super(stor, obj, FIXUP_RECORD_DELETE_OBJECT);
	}


	void Store() throws Exception {
		StorePath();
	}
}


//**************************************************************
//*** FixupUndeleteObject


class FixupUndeleteObject extends FixupObject7 {

	FixupUndeleteObject(Storage7 stor, Object7 obj, boolean recursive) {
		super(stor, obj, FIXUP_RECORD_UNDELETE_OBJECT);
		this.recursive = recursive;
	}
	
	
	void Store() throws Exception {
		StorePath();
		
		byte[] rec = new byte [1];
		rec[0] = (byte)(recursive ? 1 : 0);
		storage.hmacFunc.Hash(rec, 0, 1);
		storage.compressor.Compress(rec, 0, 1);
	}
	
	
	//
	// Data
	//
	
	boolean recursive;
}
