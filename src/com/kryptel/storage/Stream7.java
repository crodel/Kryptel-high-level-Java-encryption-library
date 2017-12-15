/*******************************************************************************

  Product:       Kryptel/Java
  File:          Stream7.java

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


import static com.kryptel.Capabilities.*;
import static com.kryptel.bslx.Conversions.*;
import static com.kryptel.storage.Kryptel.*;

import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.util.Arrays;

import com.kryptel.IDataSink;
import com.kryptel.Message;
import com.kryptel.bslx.Crc32;
import com.kryptel.bslx.SmartBuffer;
import com.kryptel.cipher.IBlockCipherParams;
import com.kryptel.cipher.ICipher;
import com.kryptel.compressor.ICompressor;


class Stream7 implements IEncryptedStream {
	
	Stream7(Object7 parent, boolean bRead, byte comprLevel) throws Exception {
		this.parent = parent;
		this.bRead = bRead;
		
		streamFile = parent.bStreamInNewFile ? parent.storage.newFile : parent.storage.contFile;
		storageMD5 = parent.bStreamInNewFile ? parent.storage.newMD5 : parent.storage.contMD5;
		
		streamFile.seek(parent.dataPos);
		parent.storage.cipherParams.SetInitVector(parent.initVector, 0, parent.storage.cipherParamBlock.cipherBlockSize);
		
		streamMD5 = MessageDigest.getInstance("MD5");
		streamMD5.reset();
		
		cipher = parent.storage.cipher;
		compressor = parent.storage.compressor;
		ioBuf = parent.storage.ioBuffer;
		currentPosition = 0;
		
		if (bRead) {
			bytesLeft = parent.dataSize;
			parent.storage.cipher.Init(new StreamDecrypt(), null);
		}
		else {
			parent.storage.compressorParams.SetLevel(comprLevel);
			compressor.Init(new StreamCompress(), null);
		}
	}
	

	public void Read(byte[] buf, int start, int size) throws Exception {
		if (!bRead) throw new Exception("Stream::Read : Can't read from a stream opened for writing.");
		
		int len;
		
		while (bytesLeft > 0 && streamBuffer.Size() < size) {
			len = (int)Math.min(bytesLeft, ioBuf.length);
			streamFile.read(ioBuf, 0, len);
			cipher.Decrypt(ioBuf, 0, len);
			bytesLeft -= len;
		}
		
		if (bytesLeft == 0 && !bReadInFull) {
			cipher.Done();
			bReadInFull = true;
			if (!Arrays.equals(streamMD5.digest(), parent.dataHash)) throw new Exception(Message.Get(Message.Code.InvalidContainer));
		}
		
		if (streamBuffer.Size() < size) throw new Exception("Stream::Read : Can't supply the requested number of bytes (the stream is too short).");
		streamBuffer.Retrieve(buf, start, size);
		currentPosition += size;
}


	public void Write(byte[] buf, int start, int size) throws Exception {
		if (bRead) throw new Exception("Stream::Write : Can't write to a stream opened for reading.");
		compressor.Compress(buf, start, size);
		streamMD5.update(buf, start, size);
		parent.dataUncomprSize += size;
		currentPosition += size;
	}


	public long Size() {
		return parent.dataUncomprSize;
	}


	public void Seek(long newPos) throws Exception {
		throw new Exception("Stream::Seek : Requested operation is illegal for this type of container.");
	}


	public void SeekEof() throws Exception {
		throw new Exception("Stream::SeekEof : Requested operation is illegal for this type of container.");
	}


	public long Pos() throws Exception {
		return currentPosition;
	}


	public boolean Eof() throws Exception {
		return bRead ? (currentPosition == Size()) : true;
	}


	public void SetEof() throws Exception {
		throw new Exception("Stream::SetEof : Requested operation is illegal for this type of container.");
	}


	public void Close() throws Exception {
		if (!parent.bStreamIsOpen) return;	// Stream has been closed already, do nothing
		try {
			if (bRead) {
				if (!bReadInFull) {
					// If reading was not complete, decrypting/decompressing cleanup have not been done properly
					parent.storage.cipherState.Reset();
					parent.storage.compressorState.Reset();
				}
			}
			else {		// Writing
				compressor.Done();
				parent.dataHash = streamMD5.digest();
				parent.storage.nextDataPos += parent.dataSize;
				
				if ((parent.storage.GetCapabilitiesMask() & CAP_RECOVERY_BLOCKS) != 0 && parent.recData != null) {			// If the recovery block should be written
					byte r[] = new byte [4];
					parent.storage.rand.nextBytes(r);
					System.arraycopy(r, 0, ioBuf, 0, 4);
					IntAsBytes(RECOVERY_BLOCK_TAG, ioBuf, 4);
					ShortAsBytes(parent.recBlockSize, ioBuf, 8);
					LongAsBytes(parent.dataSize, ioBuf, 10);
					System.arraycopy(parent.initVector, 0, ioBuf, 16, parent.storage.cipherParamBlock.cipherBlockSize);
					System.arraycopy(parent.dataHash, 0, ioBuf, 16 + parent.storage.cipherParamBlock.cipherBlockSize, 16);
					assert parent.recData.length != 0;		// Sanity check
					ShortAsBytes((short)parent.recData.length, ioBuf, 16 + parent.storage.cipherParamBlock.cipherBlockSize + 16);
					System.arraycopy(parent.recData, 0, ioBuf, 16 + parent.storage.cipherParamBlock.cipherBlockSize + 16 + 2, parent.recData.length);
					
					int start = 16 + parent.storage.cipherParamBlock.cipherBlockSize + 16 + 2 + parent.recData.length;
					Arrays.fill(ioBuf, start, parent.recBlockSize - 4, (byte)0xE8);
					IntAsBytes(Crc32.BlockCompute(ioBuf, 0, parent.recBlockSize - 4), ioBuf, parent.recBlockSize - 4);
					
					assert ((parent.recBlockSize % parent.storage.cipherParamBlock.cipherBlockSize) == 0);	// Must be a multiple of block size
					int mode = parent.storage.cipherParams.GetChainingMode();
					parent.storage.cipherParams.SetChainingMode(IBlockCipherParams.MODE_CBC);
					byte[] b = { (byte)0 };
					parent.storage.cipherParams.SetInitVector(b, 0, 1);
					parent.storage.blockCipher.Init();
					parent.storage.blockCipher.Encrypt(ioBuf, 0, parent.recBlockSize);
					parent.storage.blockCipher.Done();
					parent.storage.cipherParams.SetChainingMode(mode);			// Restore chaining mode

					streamFile.write(ioBuf, 0, parent.recBlockSize);
					storageMD5.update(ioBuf, 0, parent.recBlockSize);
					parent.storage.nextDataPos += parent.recBlockSize;
				}

				if (!parent.storage.IsNewFileActive()) new FixupAttachData(parent.storage, parent);

				// Update statistics

				assert (parent.dataSize > 0);
				parent.storage.statistics.nStreams++;
				parent.storage.statistics.uDataAreaUsed += parent.dataSize;
				parent.storage.statistics.uTotalStreamSize += parent.dataUncomprSize;
				
				if (parent.recBlockSize > 0) {
					parent.storage.statistics.nRecoveryBlocks++;
					parent.storage.statistics.uTotalRecoveryBlockSize += parent.recBlockSize;
				}
			}
		}
		catch (Exception e) {
			parent.storage.cipherState.Reset();
			parent.storage.compressorState.Reset();
			throw e;
		}
		finally {
			parent.storage.bStreamActive = false;
			parent.bStreamIsOpen = false;
		}
	}


	//
	// AutoCloseable
	//
	
	
	public void close() throws Exception {
		Close();
	}
	
	
	//
	// Data
	//
	
	
	private Object7 parent;
	private boolean bRead;
	
	private RandomAccessFile streamFile;
	private MessageDigest storageMD5;

	private MessageDigest streamMD5;
	
	private SmartBuffer streamBuffer = new SmartBuffer();
	long bytesLeft;
	boolean bReadInFull = false;
	
	long currentPosition;
	
	// Shortcuts
	ICipher cipher;
	ICompressor compressor;
	byte[] ioBuf;
	
	
	//
	// Datasinks
	//

	
	private class StreamCompress implements IDataSink {
		public void Init(Object arg) throws Exception {
			cipher.Init(new StreamEncrypt(), arg);
		}

		public void PutData(byte[] buf, int start, int size) throws Exception {
			cipher.Encrypt(buf, start, size);
		}

		public void Done() throws Exception {
			cipher.Done();
		}
	}
	
	
	private class StreamEncrypt implements IDataSink {
		public void Init(Object arg) { }

		public void PutData(byte[] buf, int start, int size) throws Exception {
			parent.dataSize += size;
			streamFile.write(buf, start, size);
			storageMD5.update(buf, start, size);
		}

		public void Done() { }
	}
	
	
	private class StreamDecrypt implements IDataSink {
		public void Init(Object arg) throws Exception {
			compressor.Init(new StreamDecompress(), arg);
		}

		public void PutData(byte[] buf, int start, int size) throws Exception {
			compressor.Decompress(buf, start, size);
		}

		public void Done() throws Exception {
			compressor.Done();
		}
	}
	
	
	private class StreamDecompress implements IDataSink {
		public void Init(Object arg) { }

		public void PutData(byte[] buf, int start, int size) throws Exception {
			streamBuffer.Store(buf, start, size);
			streamMD5.update(buf, start, size);
		}

		public void Done() { }
	}
}
