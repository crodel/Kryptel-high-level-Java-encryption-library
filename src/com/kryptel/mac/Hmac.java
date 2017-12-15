/*******************************************************************************

  Product:       Kryptel/Java
  File:          Hmac.java
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


import static com.kryptel.Capabilities.CAP_DEFAULT_CAPABILITIES;
import static com.kryptel.Constants.TYPE_HASH_FUNCTION;
import static com.kryptel.Guids.CID_HMAC;
import static com.kryptel.Guids.IID_IComponentState;
import static com.kryptel.Guids.IID_IHashFunction;
import static com.kryptel.Guids.IID_IHashFunctionParams;
import static com.kryptel.Guids.IID_IKryptelComponent;
import static com.kryptel.Guids.IID_IMacSetup;

import java.util.Arrays;
import java.util.UUID;

import com.kryptel.IComponentState;
import com.kryptel.IKryptelComponent;
import com.kryptel.Message;
import com.kryptel.hash_function.IHashFunction;
import com.kryptel.hash_function.IHashFunctionParams;


final class Hmac extends MacBase {
	Hmac(long capabilities) { }
	
	//
	// IKryptelComponent
	//

	public UUID ComponentID() { return componentID; }
	public String ComponentName() { return "HMAC"; }
	
	public Object GetInterface(UUID iid) throws Exception {
		if (iid.equals(IID_IHashFunctionParams)) {
			if (baseComp == null) throw new Exception(Message.Get(Message.Code.MacBaseNotSet));
			return baseComp;
		}
		else if (iid.equals(IID_IKryptelComponent) ||
						iid.equals(IID_IComponentState) ||
						iid.equals(IID_IMacSetup) ||
						iid.equals(IID_IHashFunction)) return this;
		return super.GetInterface(iid);
	}
	
	
	//
	// IComponentState
	//

	public IKryptelComponent Clone() throws Exception {
		IKryptelComponent myclone = new Hmac(CAP_DEFAULT_CAPABILITIES);
		if (baseComp != null) {
			IComponentState bstate = (IComponentState)baseComp.GetInterface(IID_IComponentState);
			assert (bstate != null);
			
			IMacSetup setup = (IMacSetup)myclone.GetInterface(IID_IMacSetup);
			setup.SetBase(bstate.Clone());
			
			if (macKey != null) setup.SetKey(macKey, 0, macKey.length);
		}
		return myclone;
	}
	
	
	//
	// AutoCloseable
	//

	public void close() throws Exception {
		if (ipad != null) {
			assert (opad != null);
			Arrays.fill(ipad, (byte)0);
			Arrays.fill(opad, (byte)0);
		}
		super.close();
	}

	
	//
	// IMacSetup
	//

	public void SetBase(UUID cid) throws Exception {
		super.SetBase(cid);
		CheckBase();
	}
	
	public void SetBase(IKryptelComponent comp) throws Exception {
		super.SetBase(comp);
		CheckBase();
	}
	
	public void SetKey(byte[] key, int start, int size) throws Exception {
		super.SetKey(key, start, size);
	}

	
	//
	// IHashFunction
	//

	public void Init() throws Exception {
		super.Init();
		InitHmac();
	
		hashFunc = (IHashFunction)baseComp.GetInterface(IID_IHashFunction);
		hashFunc.Init();
		hashFunc.Hash(ipad, 0, ipad.length);
	}
	
	public void Hash(byte[] src, int start, int len) throws Exception {
		if (currentState != State.Hashing) throw new Exception(Message.Get(Message.Code.InvalidState));
		if (len > 0) hashFunc.Hash(src, start, len);
	}
	
	public byte[] Done() throws Exception {
		if (currentState != State.Hashing) throw new Exception(Message.Get(Message.Code.InvalidState));
		byte[] textHash = hashFunc.Done();
		
		currentState = State.Idle;
		
		hashFunc.Init();
		hashFunc.Hash(opad, 0, opad.length);
		hashFunc.Hash(textHash, 0, textHash.length);
		return hashFunc.Done();
	}

	
  //
  // Private data and methods
  //

  static UUID componentID = CID_HMAC;
	
	private byte[] ipad = null;
	private byte[] opad = null;
	
	IHashFunctionParams hashFuncParams;
	IHashFunction hashFunc;
	
	
	private void CheckBase() throws Exception {
		if ((baseComp.ComponentType() & TYPE_HASH_FUNCTION) == 0) {
			baseComp = null;
			throw new Exception(Message.Get(Message.Code.InvalidMacBase));
		}
		hashFuncParams = (IHashFunctionParams)baseComp.GetInterface(IID_IHashFunctionParams);
	}
	
	
	private void InitHmac() throws Exception {
		if (baseComp == null) throw new Exception(Message.Get(Message.Code.MacBaseNotSet));
		
		int blsize = hashFuncParams.GetHashBlockSize();

		if (ipad != null) {
			assert (opad != null);
			if (ipad.length != blsize) {
				Arrays.fill(ipad, (byte)0);
				Arrays.fill(opad, (byte)0);
				ipad = null;
				opad = null;
			}
		}
		
		if (ipad == null) {
			ipad = new byte [blsize];
			opad = new byte [blsize];
		}
		
		Arrays.fill(ipad, (byte)0x36);
		Arrays.fill(opad, (byte)0x5C);
		
		for (int i = 0; i < Math.min(macKey.length, blsize); i++) {
			ipad[i] ^= macKey[i];
			opad[i] ^= macKey[i];
		}
	}
}
