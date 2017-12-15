/*******************************************************************************

  Product:       Kryptel/Java
  File:          HashBase.java
  Description:   https://www.kryptel.com/articles/developers/java/hash.adding_hash_function.php

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


package com.kryptel.hash_function;


import static com.kryptel.Constants.DEFAULT_VALUE;
import static com.kryptel.Constants.TYPE_HASH_FUNCTION;
import static com.kryptel.Guids.IID_IComponentState;
import static com.kryptel.Guids.IID_IHashFunction;
import static com.kryptel.Guids.IID_IHashFunctionParams;
import static com.kryptel.Guids.IID_IKryptelComponent;
import static com.kryptel.Guids.IID_IMemoryBlockHash;

import java.util.UUID;

import com.kryptel.IComponentState;
import com.kryptel.IKryptelComponent;
import com.kryptel.Message;


abstract class HashBase implements	IKryptelComponent,
																		IComponentState,
																		AutoCloseable,
																		IHashFunctionParams {

	HashBase(long capabilities) {
		compCapabilities = capabilities;
	}
	
	
	//
	// IKryptelComponent
	//
	// Children must implement ComponentID and ComponentName
	//

	public long ComponentType() { return componentType; }
	
	public Object GetInterface(UUID iid) {
		if (iid.equals(IID_IKryptelComponent) || iid.equals(IID_IComponentState) || iid.equals(IID_IHashFunctionParams)) return this;

		if (iid.equals(IID_IHashFunction)) {
			if (hashFunction == null) hashFunction = new HashFunction();
			return hashFunction;
		}
		
		if (iid.equals(IID_IMemoryBlockHash)) {
			if (blockHashFunction == null) blockHashFunction = new MemoryBlockHash();
			return blockHashFunction;
		}

		return null;
	}
	
	public void DiscardComponent() { Reset(); }
	
	
	//
	// IComponentState
	//
	// Children must implement Clone
	// 

	protected long compCapabilities;

	public ComponentState GetState() { return (currentState == State.Idle) ? ComponentState.ComponentIdle : ComponentState.ComponentBusy; }

	public void Reset() { currentState = State.Idle; }

	public IKryptelComponent Clone() throws Exception {
		IKryptelComponent comp = ComponentLoader.CreateComponent(ComponentID(), compCapabilities);
		IHashFunctionParams params = (IHashFunctionParams)comp.GetInterface(IID_IHashFunctionParams);
		params.SetHashSize(GetHashSize());
		params.SetPasses(GetPasses());
		params.SetScheme(GetScheme());
		return comp;
	}

	
	//
	// AutoCloseable
	//

	public void close() throws Exception { DiscardComponent(); }
	
	
	//
	// IHashFunctionParams
	//

	public int GetHashSize() { return hashSize; }
	public int GetPasses() { return hashPasses; }
	public byte GetScheme() { return hashScheme; }
	
	public int GetHashBlockSize() {		// Used by HMAC, by default it is 64 bytes
		return 64;
	}
	
	public void SetHashSize(int size) throws Exception {
		if (currentState != State.Idle) throw new Exception(Message.Get(Message.Code.InvalidState));

		if (size != DEFAULT_VALUE) {
			for (int hs: hashFunctionInfo.ValidHashSizes) {
				if (hs == size) {
					hashSize = size;
					return;
				}
			}
			throw new Exception(Message.Get(Message.Code.InvalidArg));
		}
		else
			hashSize = DEFAULT_HASH_SIZE;
	}
	
	public void SetPasses(int passes) throws Exception {
		if (currentState != State.Idle) throw new Exception(Message.Get(Message.Code.InvalidState));

		if (passes != DEFAULT_VALUE) {
			for (int ps: hashFunctionInfo.ValidPasses) {
				if (ps == passes) {
					hashPasses = passes;
					return;
				}
			}
			throw new Exception(Message.Get(Message.Code.InvalidArg));
		}
		else
			hashPasses = DEFAULT_PASSES;
	}

	public void SetScheme(byte scheme) throws Exception {
		if (currentState != State.Idle) throw new Exception(Message.Get(Message.Code.InvalidState));

		if (scheme >= 1 && scheme <= hashFunctionInfo.Schemes.length)
			hashScheme = scheme;
		else if (scheme == DEFAULT_VALUE)
			hashScheme = DEFAULT_SCHEME;
		else
			throw new Exception(Message.Get(Message.Code.InvalidArg));
	}
	
	public HashFunctionInfo GetInfo() {
		return hashFunctionInfo;
	}

	
	//
	// IHashFunction
	//

	private class HashFunction implements IHashFunction {
		public void Init() throws Exception {
			if (currentState != State.Idle) throw new Exception(Message.Get(Message.Code.InvalidState));
			InitImpl();
			currentState = State.Hashing;
		}
		
		public void Hash(byte[] src, int start, int len) throws Exception {
			if (currentState != State.Hashing) throw new Exception(Message.Get(Message.Code.InvalidState));
			if (len > 0) HashImpl(src, start, len);
		}
		
		public byte[] Done() throws Exception {
			if (currentState != State.Hashing) throw new Exception(Message.Get(Message.Code.InvalidState));
			currentState = State.Idle;
			return DoneImpl();
		}
	}
	
	
	//
	// IMemoryBlockHash
	//

	private class MemoryBlockHash implements IMemoryBlockHash {
		public byte[] HashBlock(final byte[] src, int start, int len) throws Exception {
			if (currentState != State.Idle) throw new Exception(Message.Get(Message.Code.InvalidState));
      InitImpl();
      if (len > 0) HashImpl(src, start, len);
      return DoneImpl();
		}
		
		public byte[] HashUtf8String(String str) throws Exception {
			byte[] byteSeq = str.getBytes("UTF8");
			return HashBlock(byteSeq, 0, byteSeq.length);
		}
		
		public byte[] HashWideString(String str) throws Exception {
			byte[] byteSeq = str.getBytes("UnicodeLittleUnmarked");
			return HashBlock(byteSeq, 0, byteSeq.length);
		}
	}

	
  //
  // Private data and methods
  //
	
  static long componentType = TYPE_HASH_FUNCTION;
	
	protected int DEFAULT_HASH_SIZE = -1;
	protected int DEFAULT_PASSES = -1;
	protected byte DEFAULT_SCHEME = -1;
	
	protected HashFunctionInfo hashFunctionInfo;

	protected int hashSize;
	protected int hashPasses;
	protected byte hashScheme;

	private enum State { Idle, Hashing };
	private State currentState = State.Idle;
	
	private HashFunction hashFunction;
	private MemoryBlockHash blockHashFunction;
	
	
	//
	// Hash function actual implementation
	//
	
  protected abstract void InitImpl();
  protected abstract void HashImpl(byte[] buffer, int start, int size);
  protected abstract byte[] DoneImpl();
}
