/*******************************************************************************

  Product:       Kryptel/Java
  File:          BlockCipherBase.java
  Description:   https://www.kryptel.com/articles/developers/java/cipher.adding_cipher.php

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


package com.kryptel.cipher;


import static com.kryptel.Constants.DEFAULT_BUFFER_SIZE;
import static com.kryptel.Constants.DEFAULT_VALUE;
import static com.kryptel.Constants.TYPE_BLOCK_CIPHER;
import static com.kryptel.Guids.IID_IBlockCipher;
import static com.kryptel.Guids.IID_IBlockCipherParams;
import static com.kryptel.Guids.IID_ICipher;
import static com.kryptel.Guids.IID_ICipherParams;
import static com.kryptel.Guids.IID_IComponentState;
import static com.kryptel.Guids.IID_IKryptelComponent;
import static com.kryptel.Guids.IID_IRawBlockCipher;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;

import com.kryptel.IComponentCapabilities;
import com.kryptel.IComponentState;
import com.kryptel.IDataSink;
import com.kryptel.IKryptelComponent;
import com.kryptel.Message;


abstract class BlockCipherBase implements IKryptelComponent,
																					IComponentState,
																					IComponentCapabilities,
																					IBlockCipherParams,
																					IRawBlockCipher {

	BlockCipherBase(long capabilities) {
		compCapabilities = capabilities;
	}
	
	//
	// IKryptelComponent
	//
	// Children must implement ComponentID and ComponentName
	//
	
	public long ComponentType() { return componentType; }
	
	public Object GetInterface(UUID iid) {
		if (iid.equals(IID_IKryptelComponent) ||
				iid.equals(IID_IComponentState) ||
				iid.equals(IID_ICipherParams) ||
				iid.equals(IID_IBlockCipherParams) ||
				iid.equals(IID_IRawBlockCipher)) return this;

		if (iid.equals(IID_IBlockCipher)) {
			if (blockCipher == null) blockCipher = new BlockCipher();
			return blockCipher;
		}

		if (iid.equals(IID_ICipher)) {
			if (streamCipher == null) streamCipher = new StreamCipher();
			return streamCipher;
		}
		
		return null;
	}
	
	public void DiscardComponent() {
		Reset();
		
		if (cipherKey != null) {
			Arrays.fill(cipherKey, (byte)0);
			cipherKey = null;
		}
		if (userKey != null) {
			Arrays.fill(userKey, (byte)0);
			userKey = null;
		}
		if (initVector != null) {
			Arrays.fill(initVector, (byte)0);
			initVector = null;
		}
		if (cipherFeed != null) {
			Arrays.fill(cipherFeed, (byte)0);
	  	cipherFeed = null;
		}
		if (ctrCounter != null) {
			Arrays.fill(ctrCounter, (byte)0);
			ctrCounter = null;
		}
	}
	
	
	//
	// IComponentState
	//

	public ComponentState GetState() { return (currentState == State.Idle) ? ComponentState.ComponentIdle : ComponentState.ComponentBusy; }

	public void Reset() { currentState = State.Idle; }

	public IKryptelComponent Clone() throws Exception {
		IKryptelComponent comp = ComponentLoader.CreateComponent(ComponentID(), compCapabilities);
		IBlockCipherParams params = (IBlockCipherParams)comp.GetInterface(IID_IBlockCipherParams);
		params.SetKeySize(GetKeySize());
		params.SetRounds(GetRounds());
		params.SetScheme(GetScheme());
		params.SetBlockSize(GetBlockSize());
		params.SetChainingMode(GetChainingMode());
		byte[] key = GetKey();
		if (key != null) params.SetKey(key, 0, key.length);
		byte[] vector = GetInitVector();
		if (vector != null) params.SetInitVector(vector, 0, vector.length);
		return comp;
	}

	
	//
	// IComponentCapabilities
	//
	
	protected long compCapabilities;

	public long GetCapabilitiesMask() { return compCapabilities; }
	
	public void SetCapabilitiesMask(long capabilities) { compCapabilities = capabilities; }
	
	
	//
	// AutoCloseable
	//

	public void close() throws Exception { DiscardComponent(); }
	
	
  //
  // ICipherParams
  //
	// Children must implement SetKeySize, SetRounds, SetScheme, and GetInfo
	//
	
	public int GetKeySize() { return cipherKeySize; }
	public int GetRounds() { return cipherRounds; }
	public byte GetScheme() { return cipherScheme; }
	public byte[] GetKey() { return userKey; }

	public void SetKeySize(int size) throws Exception {
		CheckState(State.Idle);

		if (size != DEFAULT_VALUE) {
			for (int ks: cipherInfo.ValidKeySizes) {
				if (ks == size) {
					cipherKeySize = size;
					return;
				}
			}
			throw new Exception(Message.Get(Message.Code.InvalidKeySize));
		}
		else
			cipherKeySize = DEFAULT_KEY_SIZE;
		
		keyNeedsExpanding = true;
	}
	
	public void SetRounds(int rounds) throws Exception {
		CheckState(State.Idle);

		if (rounds != DEFAULT_VALUE) {
			for (int rd: cipherInfo.ValidRounds) {
				if (rd == rounds) {
					cipherRounds = rd;
					return;
				}
			}
			throw new Exception(Message.Get(Message.Code.InvalidRounds));
		}
		else
			cipherRounds = DEFAULT_ROUNDS;
		
		keyNeedsExpanding = true;
	}
	
	public void SetScheme(byte scheme) throws Exception {
		CheckState(State.Idle);
		if (scheme >= 1 && scheme <= cipherInfo.Schemes.length)
			cipherScheme = scheme;
		else if (scheme == DEFAULT_VALUE)
		  cipherScheme = DEFAULT_SCHEME;
		else
			throw new Exception(Message.Get(Message.Code.InvalidArg));
		
		keyNeedsExpanding = true;
	}

	public void SetKey(byte[] key, int start, int size) throws Exception {
		CheckState(State.Idle);
		if (userKey != null) Arrays.fill(userKey, (byte)0);
		userKey = Arrays.copyOfRange(key, start, start + size);
		keyNeedsExpanding = true;
	}
	
	public CipherInfo GetInfo() {
		return cipherInfo;
	}

	
  //
  // IBlockCipherParams
  //
	// Children must implement SetBlockSize
	//

	public int GetBlockSize() { return cipherBlockSize; }
	public int GetChainingMode() { return chainingMode; }
	public byte[] GetInitVector() { return initVector; }

	public void SetBlockSize(int size) throws Exception {
		CheckState(State.Idle);

		if (size != DEFAULT_VALUE) {
			for (int bs: cipherInfo.ValidBlockSizes) {
				if (bs == size) {
					cipherBlockSize = size;
					return;
				}
			}
			throw new Exception(Message.Get(Message.Code.InvalidBlockSize));
		}
		else
			cipherBlockSize = DEFAULT_BLOCK_SIZE;
		
		keyNeedsExpanding = true;
	}
	
	public void SetChainingMode(int mode) { chainingMode = mode; }
	
	public void SetInitVector(byte[] vector, int start, int size) throws Exception {
		CheckState(State.Idle);
		if (initVector != null) Arrays.fill(initVector, (byte)0);		// Erase old vector
		initVector = Arrays.copyOfRange(vector, start, start + size);
	}

	
  //
  // IRawBlockCipher
  //

	public void EncryptBlock(byte[] dst, int to, byte[] src, int from) throws Exception {
		SetupKey();
		EncryptBasicBlock(dst, to, src, from);
	}
	
	public void DecryptBlock(byte[] dst, int to, byte[] src, int from) throws Exception {
		SetupKey();
		DecryptBasicBlock(dst, to, src, from);
	}

	
  //
  // IBlockCipher
  //

	private class BlockCipher implements IBlockCipher {
		public void Init() throws Exception {
			CheckState(State.Idle);
			SetupKey();
			SetupFeeds();
			currentState = State.FirstBlockOp;
		}
	
		public void Encrypt(byte[] buf, int start, int size) throws Exception {
			if (currentState != State.BlockEncryption && currentState != State.FirstBlockOp) throw new Exception(Message.Get(Message.Code.InvalidState));
			if (currentState == State.FirstBlockOp) currentState = State.BlockEncryption;
			if ((size % cipherBlockSize) != 0) throw new Exception(Message.Get(Message.Code.NotBlockSizeMultiple));
			EncryptData(buf, start, size / cipherBlockSize);
		}
	
		public void Decrypt(byte[] buf, int start, int size) throws Exception {
			if (currentState != State.BlockDecryption && currentState != State.FirstBlockOp) throw new Exception(Message.Get(Message.Code.InvalidState));
			if (currentState == State.FirstBlockOp) currentState = State.BlockDecryption;
			if ((size % cipherBlockSize) != 0) throw new Exception(Message.Get(Message.Code.NotBlockSizeMultiple));
			DecryptData(buf, start, size / cipherBlockSize);
		}
	
		public void Done() throws Exception {
			currentState = State.Idle;
		}
	}

	
  //
  // ICipher
  //

	private class StreamCipher implements ICipher {
  	private IDataSink dataSink;
  	private Object sinkArg;
  	byte[] Buffer;
  	int bufPtr;
  	
  	SecureRandom rand;
  	byte[] header = new byte [17];
  	boolean removeHeader;

  	public void Init(IDataSink callback, Object arg) throws Exception {
			CheckState(State.Idle);
			SetupKey();
			SetupFeeds();
			
			if (rand == null) {
				rand = new SecureRandom();
				assert (cipherBlockSize != 0);
				rand.setSeed(rand.generateSeed(cipherBlockSize));
			}
			
			if (Buffer == null) {
				Buffer = new byte [DEFAULT_BUFFER_SIZE];
				assert ((Buffer.length % cipherBlockSize) == 0);
			}
			
  		if (callback == null) throw new Exception(Message.Get(Message.Code.InvalidArg));
  		dataSink = callback;
  		sinkArg = arg;
  		dataSink.Init(sinkArg);
			
			currentState = State.FirstOp;
		}
		
		public void Encrypt(byte[] src, int start, int size) throws Exception {
			if (currentState == State.FirstOp) {
				rand.nextBytes(header);
				header[0] &= (byte)0x0F;
				header[0] += 2;
				if ((header[0] % cipherBlockSize) == 0) header[0]++;
				bufPtr = header[0];
		    System.arraycopy(header, 0, Buffer, 0, bufPtr);
				currentState = State.Encryption;
			}
			CheckState(State.Encryption);
			
			int len;
			while (size > 0) {
				len = Math.min(size, (Buffer.length - bufPtr));
				System.arraycopy(src, start, Buffer, bufPtr, len);
				start += len;
				size -= len;
				
				bufPtr += len;
				if (bufPtr == Buffer.length) {
					EncryptData(Buffer, 0, Buffer.length / cipherBlockSize);
					dataSink.PutData(Buffer, 0, Buffer.length);
					bufPtr = 0;
				}
			}
		}
		
		public void Decrypt(byte[] src, int start, int size) throws Exception {
			if (currentState == State.FirstOp) {
				bufPtr = 0;
				removeHeader = true;
				currentState = State.Decryption;
			}
			CheckState(State.Decryption);
			
			int len, ofs;
			while (size > 0) {
				len = Math.min(size, (Buffer.length - bufPtr));
				System.arraycopy(src, start, Buffer, bufPtr, len);
				start += len;
				size -= len;
				
				bufPtr += len;
				if (bufPtr == Buffer.length) {
					// Process the data except the last block because it may contain the aligning tail
					DecryptData(Buffer, 0, Buffer.length / cipherBlockSize - 1);
					// Remove the header if necessary
					if (removeHeader) {
						ofs = Buffer[0];
						removeHeader = false;
					}
					else
						ofs = 0;
					dataSink.PutData(Buffer, ofs, Buffer.length - ofs - cipherBlockSize);
					System.arraycopy(Buffer, Buffer.length - cipherBlockSize, Buffer, 0, cipherBlockSize);
					bufPtr = cipherBlockSize;
				}
			}
		}
		
		public void Done() throws Exception {
			if (currentState == State.Encryption) {
				// Align to block size
				int n = (bufPtr + 1) % cipherBlockSize;
				if (n > 0) {
					n = cipherBlockSize - n;
					byte[] tail = new byte [n];
					rand.nextBytes(tail);
			    System.arraycopy(tail, 0, Buffer, bufPtr, n);
					bufPtr += n;
				}
				Buffer[bufPtr++] = (byte)(n + 1);

				EncryptData(Buffer, 0, bufPtr / cipherBlockSize);
				dataSink.PutData(Buffer, 0, bufPtr);
			}
			
			else if (currentState == State.Decryption) {
				if ((bufPtr % cipherBlockSize) != 0) throw new Exception(Message.Get(Message.Code.NotBlockSizeMultiple));

				DecryptData(Buffer, 0, bufPtr / cipherBlockSize);
				
				// Remove the header if necessary
				int ofs = removeHeader ? Buffer[0] : 0;
				if (ofs < 0 || ofs >= bufPtr) throw new Exception(Message.Get(Message.Code.InvalidCipherStreamHeader)); 

				bufPtr -= Buffer[bufPtr - 1];
				if ((bufPtr - ofs) < 0) throw new Exception(Message.Get(Message.Code.InvalidCipherStream));
				if ((bufPtr - ofs) > 0) dataSink.PutData(Buffer, ofs, bufPtr - ofs);
			}
			
			else if (currentState != State.FirstOp)
				throw new Exception(Message.Get(Message.Code.InvalidState));
			
			dataSink.Done();
			currentState = State.Idle;
		}
	}

	
  //
  // Private data and methods
  //

  static long componentType = TYPE_BLOCK_CIPHER;

  protected enum State { Idle, FirstOp, Encryption, Decryption, FirstBlockOp, BlockEncryption, BlockDecryption };
  protected State currentState = State.Idle;
	
	static final int DEFAULT_CHAINING_MODE = MODE_CTR;
	protected int chainingMode = DEFAULT_CHAINING_MODE;
	
	protected int DEFAULT_KEY_SIZE = -1;
	protected int DEFAULT_BLOCK_SIZE = -1;
	protected int DEFAULT_ROUNDS = -1;
	protected byte DEFAULT_SCHEME = -1;
	
	protected CipherInfo cipherInfo;
	
	protected int cipherKeySize;
	protected int cipherBlockSize;
	protected int cipherRounds;
	protected byte cipherScheme;

	protected byte[] cipherKey;
	private byte[] userKey;
	protected boolean keyNeedsExpanding = true;

	private byte[] initVector;
	private byte[] cipherFeed;
	private byte[] ctrCounter;
	
	private BlockCipher blockCipher;
	private StreamCipher streamCipher;

	
	void CheckState(State state) throws Exception {
		if (currentState != state) throw new Exception(Message.Get(Message.Code.InvalidState));
	}
	
	private void SetupKey() throws Exception {
		if (keyNeedsExpanding) {
			if (userKey == null || userKey.length == 0) throw new Exception(Message.Get(Message.Code.KeyMustBeSet));
			if (cipherKey != null) Arrays.fill(cipherKey, (byte)0);
			
			cipherKey = Arrays.copyOf(userKey, cipherKeySize);
			ExpandKey();
			keyNeedsExpanding = false;
		}
	}

	private void SetupFeeds() {
    if (cipherFeed != null && cipherFeed.length != cipherBlockSize) {
    	Arrays.fill(cipherFeed, (byte)0);
    	Arrays.fill(ctrCounter, (byte)0);
    	cipherFeed = null;
    	ctrCounter = null;
    }

    if (initVector != null && initVector.length > 0)
    	cipherFeed = Arrays.copyOf(initVector, cipherBlockSize);
    else {
    	if (cipherFeed == null) cipherFeed = new byte[cipherBlockSize];
    	Arrays.fill(cipherFeed, (byte)0);
    }

    EncryptBasicBlock(cipherFeed, 0, cipherFeed, 0);

    if (ctrCounter == null) ctrCounter = new byte[cipherBlockSize];
    System.arraycopy(cipherFeed, 0, ctrCounter, 0, cipherBlockSize);
  }
	
  private void EncryptData(byte[] block, int start, int nblocks) {
    int offset = 0;

    switch (chainingMode) {
      case MODE_ECB:
        for (int i = 0; i < nblocks; i++) {
          EncryptBasicBlock(block, start + offset, block, start + offset);
          offset += cipherBlockSize;
        }
        break;

      case MODE_CBC:
        for (int i = 0; i < nblocks; i++) {
          for (int j = 0; j < cipherBlockSize; j++) block[start + offset + j] ^= cipherFeed[j];
          EncryptBasicBlock(block, start + offset, block, start + offset);
          System.arraycopy(block, start + offset, cipherFeed, 0, cipherBlockSize);
          offset += cipherBlockSize;
        }
        break;

      case MODE_CFB:
        for (int i = 0; i < nblocks; i++) {
          for (int j = 0; j < cipherBlockSize; j++) block[start + offset + j] ^= cipherFeed[j];
          EncryptBasicBlock(cipherFeed, 0, block, start + offset);
          offset += cipherBlockSize;
        }
        break;

      case MODE_OFB:
        for (int i = 0; i < nblocks; i++) {
          for (int j = 0; j < cipherBlockSize; j++) block[start + offset + j] ^= cipherFeed[j];
          EncryptBasicBlock(cipherFeed, 0, cipherFeed, 0);
          offset += cipherBlockSize;
        }
        break;

      case MODE_CTR:
        for (int i = 0; i < nblocks; i++) {
          EncryptBasicBlock(cipherFeed, 0, ctrCounter, 0);
          for (int j = 0; j < cipherBlockSize; j++) block[start + offset + j] ^= cipherFeed[j];
          for (int j = 0; j < cipherBlockSize; j++) {   // Increase counter
          	ctrCounter[j]++;
            if (ctrCounter[j] != 0) break;
          }
          offset += cipherBlockSize;
        }
        break;
    }
  }

  private void DecryptData(byte[] block, int start, int nblocks) {
    int offset = 0;

    switch (chainingMode) {
      case MODE_ECB:
        for (int i = 0; i < nblocks; i++) {
          DecryptBasicBlock(block, start + offset, block, start + offset);
          offset += cipherBlockSize;
        }
        break;

      case MODE_CBC:
        for (int i = 0; i < nblocks; i++) {
        	System.arraycopy(block, start + offset, ctrCounter, 0, cipherBlockSize);
          DecryptBasicBlock(block, start + offset, block, start + offset);
          for (int j = 0; j < cipherBlockSize; j++) block[start + offset + j] ^= cipherFeed[j];
          System.arraycopy(ctrCounter, 0, cipherFeed, 0, cipherBlockSize);
          offset += cipherBlockSize;
        }
        break;

      case MODE_CFB:
        for (int i = 0; i < nblocks; i++) {
        	System.arraycopy(block, start + offset, ctrCounter, 0, cipherBlockSize);
          for (int j = 0; j < cipherBlockSize; j++) block[start + offset + j] ^= cipherFeed[j];
          EncryptBasicBlock(cipherFeed, 0, ctrCounter, 0);
          offset += cipherBlockSize;
        }
        break;

      case MODE_OFB:
        for (int i = 0; i < nblocks; i++) {
          for (int j = 0; j < cipherBlockSize; j++) block[start + offset + j] ^= cipherFeed[j];
          EncryptBasicBlock(cipherFeed, 0, cipherFeed, 0);
          offset += cipherBlockSize;
        }
        break;

      case MODE_CTR:
        for (int i = 0; i < nblocks; i++) {
          EncryptBasicBlock(cipherFeed, 0, ctrCounter, 0);
          for (int j = 0; j < cipherBlockSize; j++) block[start + offset + j] ^= cipherFeed[j];
          for (int j = 0; j < cipherBlockSize; j++) {   // Increase counter
          	ctrCounter[j]++;
            if (ctrCounter[j] != 0) break;
          }
          offset += cipherBlockSize;
        }
        break;
    }
  }
	
	
	//
	// These methods actually implement the block cipher
	//

  protected abstract void ExpandKey();
  protected abstract void EncryptBasicBlock(byte[] dst, int to, byte[] src, int from);
  protected abstract void DecryptBasicBlock(byte[] dst, int to, byte[] src, int from);
}
