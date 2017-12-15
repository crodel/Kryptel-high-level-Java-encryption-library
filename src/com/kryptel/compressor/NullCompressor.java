/*******************************************************************************

  Product:       Kryptel/Java
  File:          NullCompressor.java

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


package com.kryptel.compressor;


import static com.kryptel.Capabilities.CAP_DEFAULT_CAPABILITIES;
import static com.kryptel.Constants.CT_DEFAULT_COMPRESSION;
import static com.kryptel.Constants.CT_MAX_COMPRESSION;
import static com.kryptel.Constants.CT_NO_COMPRESSION;
import static com.kryptel.Constants.TYPE_COMPRESSOR;
import static com.kryptel.Constants.TYPE_HIDDEN_COMPONENT;
import static com.kryptel.Guids.CID_NULL_COMPRESSOR;
import static com.kryptel.Guids.IID_IComponentState;
import static com.kryptel.Guids.IID_ICompressor;
import static com.kryptel.Guids.IID_ICompressorParams;
import static com.kryptel.Guids.IID_IKryptelComponent;
import static com.kryptel.Guids.IID_IMemoryBlockCompressor;

import java.util.UUID;

import com.kryptel.IComponentState;
import com.kryptel.IDataSink;
import com.kryptel.IKryptelComponent;
import com.kryptel.Message;


final class NullCompressor implements IKryptelComponent, IComponentState {
	NullCompressor(long capabilities) { }
	
	
	//
	// IKryptelComponent
	//
	
	public long ComponentType() { return componentType; }
	public UUID ComponentID() { return componentID; }
	public String ComponentName() { return "Null Compressor"; }
	
	public Object GetInterface(UUID iid) {
		if (iid.equals(IID_IKryptelComponent) || iid.equals(IID_IComponentState)) return this;

		if (iid.equals(IID_ICompressorParams)) {
			if (compressorParams == null) compressorParams = new CompressorParams();
			return compressorParams;
		}

		if (iid.equals(IID_ICompressor)) {
			if (streamCompressor == null) streamCompressor = new Compressor();
			return streamCompressor;
		}
		
		if (iid.equals(IID_IMemoryBlockCompressor)) {
			if (streamCompressor == null) streamCompressor = new Compressor();
			if (blockCompressor == null) blockCompressor = new BlockCompressor(streamCompressor);
			return blockCompressor;
		}

		return null;
	}
	
	public void DiscardComponent() { Reset(); }
	
	
	//
	// IComponentState
	//

	public ComponentState GetState() { return (currentState == State.Idle) ? ComponentState.ComponentIdle : ComponentState.ComponentBusy; }

	public void Reset() {
		currentState = State.Idle;
	}

	public IKryptelComponent Clone() {
		return new NullCompressor(CAP_DEFAULT_CAPABILITIES);
	}
	
	
	//
	// AutoCloseable
	//

	public void close() throws Exception { DiscardComponent(); }

	
	//
	// ICompressorParams
	//
	
  private class CompressorParams implements ICompressorParams {
  	public byte GetLevel() { return CT_NO_COMPRESSION; }
  	public byte GetScheme() { return 1; }
  	
  	public void SetLevel(byte level) throws Exception {
  		if (level != CT_DEFAULT_COMPRESSION && (level < CT_NO_COMPRESSION || level > CT_MAX_COMPRESSION))
  			throw new Exception(Message.Get(Message.Code.InvalidArg));
  	}

  	public void SetScheme(byte scheme) throws Exception {
  		if (scheme != 0 && scheme != 1) throw new Exception(Message.Get(Message.Code.InvalidArg));
  	}
  	
  	public CompressorInfo GetInfo() {
  		return info;
  	}
  }

	
	//
	// ICompressor
	//
	
  private class Compressor implements ICompressor {
  	private IDataSink dataSink;
  	private Object sinkArg;
  	
  	
  	public void Init(IDataSink callback, Object arg) throws Exception {
  		if (currentState != State.Idle) throw new Exception(Message.Get(Message.Code.InvalidState));
  		if (callback == null) throw new Exception(Message.Get(Message.Code.InvalidArg));
  		currentState = State.FirstOp;
  		dataSink = callback;
  		sinkArg = arg;
  		dataSink.Init(sinkArg);
  	}
  	
  	
  	public void Compress(byte[] src, int start, int size) throws Exception {
  		if (currentState == State.FirstOp)
  			currentState = State.Compressing;
  		else if (currentState != State.Compressing)
  			throw new Exception(Message.Get(Message.Code.InvalidState));
  		
  		dataSink.PutData(src, start, size);
  	}
  	
  	
  	public void Decompress(byte[] src, int start, int size) throws Exception {
   		if (currentState == State.FirstOp)
  			currentState = State.Decompressing;
  		else if (currentState != State.Decompressing)
  			throw new Exception(Message.Get(Message.Code.InvalidState));
  		
  		dataSink.PutData(src, start, size);
  	}
 	
  	
  	public void Done() throws Exception {
   		if (currentState == State.Idle) throw new Exception(Message.Get(Message.Code.InvalidState));
   		
   		dataSink.Done();
   		currentState = State.Idle;
  	}
  }
	
	
  //
  // Private data and methods
  //

	static long componentType = TYPE_COMPRESSOR | TYPE_HIDDEN_COMPONENT;
	static UUID componentID = CID_NULL_COMPRESSOR;

	private enum State { Idle, FirstOp, Compressing, Decompressing };
	private State currentState = State.Idle;
	
	private CompressorParams compressorParams;
	private Compressor streamCompressor;
	private BlockCompressor blockCompressor;
	
	private static CompressorInfo info = new CompressorInfo(new String[] { "Copying" });
}
