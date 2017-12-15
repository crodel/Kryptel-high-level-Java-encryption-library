/*******************************************************************************

  Product:       Kryptel/Java
  File:          BlockCompressor.java

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


import com.kryptel.IDataSink;
import com.kryptel.bslx.SmartBuffer;


final class BlockCompressor implements IMemoryBlockCompressor {
	BlockCompressor(ICompressor compr) { assert(compr != null); streamCompressor = compr; }
	
	public byte[] CompressBlock(final byte[] src, int start, int size) throws Exception {
		streamCompressor.Init(new DataSink(), null);
		streamCompressor.Compress(src, start, size);
		streamCompressor.Done();
		return smartBuffer.Merge();
	}
	
	public byte[] DecompressBlock(final byte[] src, int start, int size) throws Exception {
		streamCompressor.Init(new DataSink(), null);
		streamCompressor.Decompress(src, start, size);
		streamCompressor.Done();
		return smartBuffer.Merge();
	}

	public byte[] CompressUtf8String(final String str) throws Exception {
		byte[] byteSeq = str.getBytes("UTF8");
		return CompressBlock(byteSeq, 0, byteSeq.length);
	}
	
	public String DecompressUtf8String(final byte[] src, int start, int size) throws Exception {
		byte[] byteSeq = DecompressBlock(src, start, size);
		return new String(byteSeq, 0, byteSeq.length, "UTF8");
	}

	public byte[] CompressWideString(final String str) throws Exception {
		byte[] byteSeq = str.getBytes("UnicodeLittleUnmarked");
		return CompressBlock(byteSeq, 0, byteSeq.length);
	}
	
	public String DecompressWideString(final byte[] src, int start, int size) throws Exception {
		byte[] byteSeq = DecompressBlock(src, start, size);
		return new String(byteSeq, 0, byteSeq.length, "UnicodeLittleUnmarked");
	}
	
	private ICompressor streamCompressor;
	private SmartBuffer smartBuffer = new SmartBuffer();
	
	private class DataSink implements IDataSink {
		public void Init(Object arg) { smartBuffer.Empty(); }
		public void PutData(byte[] buf, int start, int bufsize) { smartBuffer.Store(buf, start, bufsize); }
		public void Done() { }
	}
}
