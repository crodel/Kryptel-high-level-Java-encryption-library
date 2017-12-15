/*******************************************************************************

  Product:       Kryptel/Java
  File:          Zip.java

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
import static com.kryptel.Constants.*;
import static com.kryptel.Guids.*;

import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import com.kryptel.IComponentState;
import com.kryptel.IDataSink;
import com.kryptel.IKryptelComponent;
import com.kryptel.Message;


final class Zip implements IKryptelComponent, IComponentState {
	Zip(long capabilities) { }
	
	
	//
	// IKryptelComponent
	//
	
	public long ComponentType() { return componentType; }
	public UUID ComponentID() { return componentID; }
	public String ComponentName() { return "ZIP"; }
	
	public Object GetInterface(UUID iid) {
		if (iid.equals(IID_IKryptelComponent) || iid.equals(IID_IComponentState)) return this;

		if (iid.equals(IID_ICompressorParams)) {
			if (compressorParams == null) compressorParams = new ZipParams();
			return compressorParams;
		}

		if (iid.equals(IID_ICompressor)) {
			if (streamCompressor == null) streamCompressor = new ZipCompressor();
			return streamCompressor;
		}
		
		if (iid.equals(IID_IMemoryBlockCompressor)) {
			if (streamCompressor == null) streamCompressor = new ZipCompressor();
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
		if (currentState != State.Idle) {
			assert (streamCompressor != null);
			streamCompressor.Reset();
			currentState = State.Idle;
		}
	}

	public IKryptelComponent Clone() {
		Zip myclone = new Zip(CAP_DEFAULT_CAPABILITIES);
		myclone.compressionLevel = compressionLevel;
		return myclone;
	}
	
	
	//
	// AutoCloseable
	//

	public void close() throws Exception { DiscardComponent(); }

	
	//
	// ICompressorParams
	//
	
  private class ZipParams implements ICompressorParams {
  	public byte GetLevel() { return compressionLevel; }
  	public byte GetScheme() { return 1; }
  	
  	public void SetLevel(byte level) throws Exception {
  		if (level == CT_DEFAULT_COMPRESSION)
  			compressionLevel = CT_AVERAGE_COMPRESSION;
  		else if (level >= CT_NO_COMPRESSION && level <= CT_MAX_COMPRESSION)
  			compressionLevel = level;
  		else
  			throw new Exception(Message.Get(Message.Code.InvalidArg));
  	}

  	public void SetScheme(byte scheme) throws Exception {
  		if (scheme != DEFAULT_VALUE && scheme != 1) throw new Exception(Message.Get(Message.Code.InvalidArg));
  	}
  	
  	public CompressorInfo GetInfo() {
  		return info;
  	}
  }

	
	//
	// ICompressor
	//
	
  private class ZipCompressor implements ICompressor {
  	private IDataSink dataSink;
  	private Object sinkArg;
  	private Deflater zipper;
  	private Inflater unzipper;
  	private byte[] buffer = new byte [DEFAULT_BUFFER_SIZE];
  	
  	
  	public void Init(IDataSink callback, Object arg) throws Exception {
  		if (currentState != State.Idle) throw new Exception(Message.Get(Message.Code.InvalidState));
  		if (callback == null) throw new Exception(Message.Get(Message.Code.InvalidArg));
  		currentState = State.FirstOp;
  		dataSink = callback;
  		sinkArg = arg;
  		dataSink.Init(sinkArg);
  	}
  	
  	
  	public void Compress(byte[] src, int start, int size) throws Exception {
  		if (currentState == State.FirstOp) {
  			currentState = State.Compressing;
  			if (zipper == null) zipper = new Deflater();
  			zipper.setLevel(compressionLevel);
  		}
  		else if (currentState != State.Compressing)
  			throw new Exception(Message.Get(Message.Code.InvalidState));
  		
  		assert(zipper.needsInput());
  		if (size == 0) return;
  		zipper.setInput(src, start, size);
  		
  		do {
   			int n = zipper.deflate(buffer, 0, buffer.length);
  			if (n != 0) dataSink.PutData(buffer, 0, n);
  		} while (!zipper.needsInput());
  	}
  	
  	
  	public void Decompress(byte[] src, int start, int size) throws Exception {
   		if (currentState == State.FirstOp) {
  			currentState = State.Decompressing;
  			if (unzipper == null) unzipper = new Inflater();
  		}
  		else if (currentState != State.Decompressing)
  			throw new Exception(Message.Get(Message.Code.InvalidState));
  		
  		assert(unzipper.needsInput());
  		if (size == 0) return;
  		unzipper.setInput(src, start, size);
  		
   		do {
   			int n = unzipper.inflate(buffer, 0, buffer.length);
  			if (n != 0) dataSink.PutData(buffer, 0, n);
   		} while (!unzipper.needsInput());
  	}
 	
  	
  	public void Done() throws Exception {
   		if (currentState == State.Compressing) {
    		assert(zipper.needsInput());
  			zipper.finish();
    		while (!zipper.finished()) {
    			int n = zipper.deflate(buffer, 0, buffer.length);
    			if (n != 0) dataSink.PutData(buffer, 0, n);
    		}
    		zipper.reset();
   		}

   		else if (currentState == State.Decompressing) {
	  		assert(unzipper.needsInput());
	  		while (!unzipper.finished()) {
	  			int n = unzipper.inflate(buffer, 0, buffer.length);
	  			if (n != 0) dataSink.PutData(buffer, 0, n);
	  		}
	  		unzipper.reset();
   		}

   		else if (currentState != State.FirstOp)
  			throw new Exception(Message.Get(Message.Code.InvalidState));
   		
   		dataSink.Done();
   		currentState = State.Idle;
  	}
  	
  	
  	void Reset() {
  		if (zipper != null) zipper.reset();
  		if (unzipper != null) unzipper.reset();
  	}
  }
	
	
  //
  // Private data and methods
  //

  static long componentType = TYPE_COMPRESSOR;
  static UUID componentID = CID_COMPRESSOR_ZIP;
	
	private byte compressionLevel = CT_AVERAGE_COMPRESSION;
	
	private enum State { Idle, FirstOp, Compressing, Decompressing };
	private State currentState = State.Idle;
	
	private ZipParams compressorParams;
	private ZipCompressor streamCompressor;
	private BlockCompressor blockCompressor;
	
	private static CompressorInfo info = new CompressorInfo(new String[] { "Deflation" });
}
