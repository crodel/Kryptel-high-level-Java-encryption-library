/*******************************************************************************

  Product:       Kryptel/Java
  File:          MacBase.java
  Description:   https://www.kryptel.com/articles/developers/java/mac.php

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


package com.kryptel.mac;


import static com.kryptel.Constants.TYPE_MAC;
import static com.kryptel.Guids.IID_IComponentState;
import static com.kryptel.Guids.IID_IHashFunction;
import static com.kryptel.Guids.IID_IHashFunctionParams;
import static com.kryptel.Guids.IID_IKryptelComponent;
import static com.kryptel.Guids.IID_IMacSetup;
import static com.kryptel.Guids.IID_IMemoryBlockHash;

import java.util.Arrays;
import java.util.UUID;

import com.kryptel.IComponentState;
import com.kryptel.IKryptelComponent;
import com.kryptel.Loader;
import com.kryptel.Message;
import com.kryptel.hash_function.IHashFunction;
import com.kryptel.hash_function.IHashFunctionParams;
import com.kryptel.hash_function.IMemoryBlockHash;


abstract class MacBase implements IKryptelComponent,
																	IComponentState,
																	IMacSetup,
																	IHashFunction,
																	IMemoryBlockHash {

  static long componentType = TYPE_MAC;

  protected enum State { Idle, Hashing };
	protected State currentState = State.Idle;
	
	protected IKryptelComponent baseComp;
	protected byte[] macKey;

	
	//
	// IKryptelComponent
	//
	// Children must implement ComponentID and ComponentName
	// Children must extend GetInterface to add missing references
	//
	
	public long ComponentType() { return componentType; }
	
	public Object GetInterface(UUID iid) throws Exception {
		if (iid.equals(IID_IKryptelComponent) ||
				iid.equals(IID_IComponentState) ||
				iid.equals(IID_IMacSetup) ||
				iid.equals(IID_IHashFunction) ||
				iid.equals(IID_IMemoryBlockHash)) return this;

		return null;
	}
	
	public void DiscardComponent() throws Exception {
		Reset();
		
		if (baseComp != null) {
			IComponentState compState = (IComponentState)baseComp.GetInterface(IID_IComponentState);
			if (compState != null) compState.Reset();
			baseComp = null;
		}
		
		if (macKey != null) Arrays.fill(macKey, (byte)0);
	}
	
	
	//
	// IComponentState
	//
	// Children must implement Clone
	// 

	public ComponentState GetState() { return (currentState == State.Idle) ? ComponentState.ComponentIdle : ComponentState.ComponentBusy; }

	public void Reset() { currentState = State.Idle; }
	
	
	//
	// AutoCloseable
	//

	public void close() throws Exception { DiscardComponent(); }
	
	
	//
	// IMacSetup
	//

	public void SetBase(UUID cid) throws Exception {
		if (currentState != State.Idle) throw new Exception(Message.Get(Message.Code.InvalidState));
		baseComp = Loader.CreateComponent(cid);
		if (baseComp == null) throw new Exception(Message.Get(Message.Code.CompNotFound));
	}
	
	public void SetBase(IKryptelComponent comp) throws Exception {
		if (currentState != State.Idle) throw new Exception(Message.Get(Message.Code.InvalidState));
		IComponentState compState = (IComponentState)comp.GetInterface(IID_IComponentState);
		baseComp = (compState != null) ? compState.Clone() : comp;
	}
	
	public void SetKey(byte[] key, int start, int size) throws Exception {
		if (currentState != State.Idle) throw new Exception(Message.Get(Message.Code.InvalidState));
		if (baseComp == null) throw new Exception(Message.Get(Message.Code.MacBaseNotSet));
		if (macKey != null) Arrays.fill(macKey, (byte)0);
		IHashFunctionParams params = (IHashFunctionParams)GetInterface(IID_IHashFunctionParams);
		assert (params != null);
		macKey = Arrays.copyOfRange(key, start, start + size);
	}
	
	
	//
	// IHashFunction
	//

	public void Init() throws Exception {
		if (currentState != State.Idle) throw new Exception(Message.Get(Message.Code.InvalidState));
		if (baseComp == null) throw new Exception(Message.Get(Message.Code.MacBaseNotSet));
		currentState = State.Hashing;
	}
	
	
	//
	// IMemoryBlockHash
	//

	public byte[] HashBlock(final byte[] src, int start, int len) throws Exception {
		if (currentState != State.Idle) throw new Exception(Message.Get(Message.Code.InvalidState));
		IHashFunction mac = (IHashFunction)GetInterface(IID_IHashFunction);
		
		mac.Init();
    if (len > 0) mac.Hash(src, start, len);
    return mac.Done();
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
