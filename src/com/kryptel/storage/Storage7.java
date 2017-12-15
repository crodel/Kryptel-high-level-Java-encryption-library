/*******************************************************************************

  Product:       Kryptel/Java
  File:          Storage7.java

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


import static com.kryptel.ApiHelpers.*;
import static com.kryptel.Capabilities.*;
import static com.kryptel.Constants.*;
import static com.kryptel.Guids.*;
import static com.kryptel.KeyIdent.*;
import static com.kryptel.bslx.Conversions.*;
import static com.kryptel.storage.Kryptel.*;

import java.io.File;
import java.io.RandomAccessFile;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;

import com.kryptel.*;
import com.kryptel.bslx.*;
import com.kryptel.cipher.*;
import com.kryptel.compressor.*;
import com.kryptel.exceptions.UserAbortException;
import com.kryptel.hash_function.*;
import com.kryptel.mac.IMacSetup;


final class Storage7 implements IKryptelComponent,
																IComponentCapabilities,
																IComponentState,
																IEncryptedStorage {
	Storage7(long capabilities) throws Exception {
		compCapabilities = capabilities;

		rand = new SecureRandom();
		rand.setSeed(rand.generateSeed(256 / 8));
	}
	
	
	//
	// IKryptelComponent
	//
	
	public long ComponentType() { return componentType; }
	public UUID ComponentID() { return componentID; }
	public String ComponentName() { return "Kryptel 7 Storage"; }
	
	public Object GetInterface(UUID iid) {
		if (iid.equals(IID_IKryptelComponent) || iid.equals(IID_IComponentCapabilities) || iid.equals(IID_IComponentState)) return this;
		if (iid.equals(IID_IEncryptedStorage)) return this;
		return null;
	}
	
	public void DiscardComponent() throws Exception { Reset(); }
	
	
	//
	// IComponentCapabilities
	//

	public long GetCapabilitiesMask() { return compCapabilities; }
	
	public void SetCapabilitiesMask(long capabilities) {
		compCapabilities = capabilities;
	}
	
	
	//
	// IComponentState
	//

	public ComponentState GetState() { return IsOpen() ? ComponentState.ComponentBusy : ComponentState.ComponentIdle; }

	public void Reset() throws Exception { Cleanup(); }

	public IKryptelComponent Clone() throws Exception {
		return new Storage7(compCapabilities);
	}
	
	
	//
	// AutoCloseable
	//

	public void close() throws Exception { DiscardComponent(); }
	
	
	//
	// IEncryptedStorage
	//
	
	public IEncryptedStorageInfo GetStorageInfo() {
		if (storageInfo == null) storageInfo = new StorageInfo();
		return storageInfo;
	}
	
	
	public CONTAINER_COMPRESSION_STRATEGY SetCompressionStrategy(CONTAINER_COMPRESSION_STRATEGY strategy) throws Exception {
		if (IsOpen()) throw new Exception("Storage::SetCompressionStrategy : Container is already open.");
		CONTAINER_COMPRESSION_STRATEGY prevStrategy = compressionStrategy;
		compressionStrategy = strategy;
		return prevStrategy;
	}
	
	
	public void SetAgentData(byte[] data, int start, int size) throws Exception {
		agentData = (data != null) ? Arrays.copyOfRange(data, start, start + size) : null;
		agentDataSize = size;
		agentDataUpdated = true;
		SetModified();
	}
	
	
	public IEncryptedObject Create(String path, IKryptelComponent cipherComp, IKryptelComponent compressorComp, IKryptelComponent hashFuncComp, UUID agent, Object arg, IKeyCallback keyFunc) throws Exception {
		if (IsOpen()) throw new Exception("Storage::Create : Container is already open.");

		try {
			contPath = path;
			File cf = new File(contPath);
			if (cf.exists()) throw new Exception("Storage::Create : File already exists.");
			
			statistics = new StorageStatistics();
			
			SetupComponents(cipherComp, compressorComp, hashFuncComp);
	
			cipherID = this.cipherComp.ComponentID();
			cipherName = this.cipherComp.ComponentName();
			cipherParamBlock = new CipherParameters(cipherParams.GetKeySize(), cipherParams.GetBlockSize(), cipherParams.GetRounds(), cipherParams.GetScheme(), cipherParams.GetChainingMode());
			cipherScheme = cipherParams.GetInfo().Schemes[cipherParamBlock.cipherScheme - 1];
	
			compressorID = this.compressorComp.ComponentID();
			compressorName = this.compressorComp.ComponentName();
			compressorParamBlock = new CompressorParameters(compressorParams.GetLevel(), compressorParams.GetScheme());
			compressorScheme = compressorParams.GetInfo().Schemes[compressorParamBlock.compressorScheme - 1];
			
			hashFunctionID = this.hashFunctionComp.ComponentID();
			hashFunctionName = this.hashFunctionComp.ComponentName();
			hashFunctionParamBlock = new HashFunctionParameters(hashFunctionParams.GetHashSize(), hashFunctionParams.GetPasses(), hashFunctionParams.GetScheme());
			hashFunctionScheme = hashFunctionParams.GetInfo().Schemes[hashFunctionParamBlock.hashScheme - 1];
			
			bHeaderAvailable = true;
			
			// Get key
			
			int keyLen;
			keyRecord =  keyFunc.Callback(arg, cf.getName(), IKeyCallback.PASSWORDS | IKeyCallback.KEY_FILES, IDENT_NULL);
			if (keyRecord == null) throw new UserAbortException();
			if (keyRecord.keyMaterial.equals(KeyIdent.IDENT_PASSWORD)
					|| keyRecord.keyMaterial.equals(KeyIdent.IDENT_LOWERCASE_PASSWORD)
					|| keyRecord.keyMaterial.equals(KeyIdent.IDENT_PROTECTED_KEY)) {
				ConvertPassword(keyRecord, hashFunctionComp);
				keyLen = hashFunctionParamBlock.hashSize;
			}
			else {
				assert ExpectedKeyMaterial(keyRecord.keyMaterial) == IKeyCallback.BINARY_KEY;
				keyLen = BINARY_KEY_SIZE;
			}
			
			if (keyRecord.keyMaterial.equals(KeyIdent.IDENT_PROTECTED_KEY)) {
				cipherParams.SetKey(keyRecord.keyData, 0, keyRecord.keyData.length);
				cipherParams.SetInitVector(Conversions.UuidToBytes(keyRecord.keyAssociatedMaterial), 0, 16);
				int mode = cipherParams.GetChainingMode();
				cipherParams.SetChainingMode(IBlockCipherParams.MODE_CBC);
				blockCipher.Init();
				blockCipher.Encrypt(keyRecord.keyAssociatedData, 0, BINARY_KEY_SIZE);
				blockCipher.Done();
				cipherParams.SetChainingMode(mode);
				
				cipherParams.SetKey(keyRecord.keyAssociatedData, 0, hashFunctionParamBlock.hashSize);
			}
			else
				cipherParams.SetKey(keyRecord.keyData, 0, hashFunctionParamBlock.hashSize);
			
			SetupHmac(keyRecord, keyLen);
			verificationPasses = VERIFICATION_LOOP_COUNT;
			keyVerificator = ComputeVerificator(verificationPasses);
			
			// Finish creation
			
			initVector = new byte [cipherParamBlock.cipherBlockSize];
			rand.nextBytes(initVector);
			
			contAgent = agent;
			
			CreateNewFile();
			bReadOnly = false;
			bModified = true;
			
			rootObject = new Object7(this, null, null);
			statistics.nObjects = 1;
		}
		catch (Exception e) {
			Cleanup();
			throw e;
		}

		return rootObject;
	}
	
	
	public IEncryptedObject Open(String path, CONTAINER_ACCESS_MODE mode, Object arg, IKeyCallback keyFunc) throws Exception {
		if (IsOpen()) throw new Exception("Storage::Open : Container is already open.");

		try {
			contPath = path;
			contMode = mode;
			File cf = new File(contPath);
			switch (contMode) {
				case CONT_READ_WRITE:
					contFile = new RandomAccessFile(cf, "rw");
					bReadOnly = false;
					break;
				
				case CONT_ANY:
					try {
						contFile = new RandomAccessFile(cf, "rw");
						bReadOnly = false;
					}
					catch (Exception e) { }
					if (contFile != null) break;
				
				case CONT_READ_ONLY:
					contFile = new RandomAccessFile(cf, "r");
					bReadOnly = true;
					break;
			}
			
			long fileSize = contFile.length();
			if (fileSize < MIN_HEADER_SIZE) throw new Exception(Message.Get(Message.Code.InvalidContainer));
			contFile.read(ioBuffer, 0, 4);
			int tag = GetAsInt(ioBuffer, 0);
			if (tag != CONTAINER_TAG) throw new Exception(Message.Get(Message.Code.InvalidContainer));
			
			contFile.read(ioBuffer, 0, 2); ioBuffer[2] = 0; ioBuffer[3] = 0;
			int headerSize = GetAsInt(ioBuffer, 0);
			
			byte[] guid = new byte [16];
			contFile.seek(10);
			contFile.read(guid);
			if (!UuidFromBytes(guid, 0).equals(componentID)) throw new Exception(Message.Get(Message.Code.InvalidContainer));
			
			header = new byte [headerSize];
			contFile.seek(0);
			contFile.read(header);
			
			// Check header MD5
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			md5.reset();
			md5.update(header, 0, headerSize - 16);
			if (!Arrays.equals(md5.digest(), Arrays.copyOfRange(header, header.length - 16, header.length))) throw new Exception(Message.Get(Message.Code.InvalidContainer));
			
			if (GetAsShort(header, 8) > CONT_CUR_VERSION) throw new Exception(Message.Get(Message.Code.OldHandlerVersion));
			
			statistics = new StorageStatistics();
			
			contAgent = UuidFromBytes(header, 26);
			
			cipherID = UuidFromBytes(header, 42);
			compressorID = UuidFromBytes(header, 58);
			hashFunctionID = UuidFromBytes(header, 74);
			
			cipherParamBlock = new CipherParameters(GetAsInt(header, 90), GetAsInt(header, 94), GetAsInt(header, 98), (byte)GetAsInt(header, 102), GetAsInt(header, 106));
			compressorParamBlock = new CompressorParameters(DEFAULT_COMPRESSION_LEVEL, (byte)GetAsInt(header, 110));
			hashFunctionParamBlock = new HashFunctionParameters(GetAsInt(header, 114), GetAsInt(header, 118), (byte)GetAsInt(header, 122));
			
			keyMaterial = UuidFromBytes(header, 126);
			int asLen = GetAsShort(header, 142);

			int pos = 144;
			
			if (keyMaterial.equals(KeyIdent.IDENT_PROTECTED_KEY)) {
				if (asLen != 16) throw new Exception(Message.Get(Message.Code.InvalidContainer));
				keyAssociatedMaterial = UuidFromBytes(header, pos + 2);
				pos += 16;
			}
			else if (!keyMaterial.equals(KeyIdent.IDENT_PASSWORD)
						&& !keyMaterial.equals(KeyIdent.IDENT_LOWERCASE_PASSWORD)
						&& ExpectedKeyMaterial(keyMaterial) != IKeyCallback.BINARY_KEY) throw new Exception(Message.Get(Message.Code.UnsupportedKeyMaterial));
			else {
				assert asLen == 0;
			}
			
			verificationPasses = GetAsInt(header, pos);
			pos += 4;
			keyVerificator = Arrays.copyOfRange(header, pos, pos + hashFunctionParamBlock.hashSize);
			pos += hashFunctionParamBlock.hashSize;
			
			// Agent data
			
			hdrAgentDataPos = pos;
			agentDataSize = GetAsInt(header, pos);
			pos += 4;
			agentDataPos = GetAsLong(header, pos);
			agentDataPos &= 0x0000FFFFFFFFFFFFL;
			pos += 6 + hashFunctionParamBlock.hashSize;
	
			statistics.uAgentDataSize = agentDataSize;
			statistics.uBaseDataAreaSize = agentDataPos - headerSize;
			
			// Directory
			
			hdrDirDataPos = pos;
			directoryPos = agentDataPos + agentDataSize;
			directorySize = GetAsLong(header, pos);
			directorySize &= 0x0000FFFFFFFFFFFFL;
			pos += 6;
			statistics.uDirectorySize = directorySize;
			
			int diriv = pos;
			pos += cipherParamBlock.cipherBlockSize;
			int dirhm = pos;
			pos += hashFunctionParamBlock.hashSize;
	
			// Load component strings and setup components
			
			int len = GetAsShort(header, pos) * 2; pos += 2;
			cipherName =  new String(header, pos, len, "UnicodeLittleUnmarked"); pos += len;
			len = GetAsShort(header, pos) * 2; pos += 2;
			cipherScheme =  new String(header, pos, len, "UnicodeLittleUnmarked"); pos += len;
	
			len = GetAsShort(header, pos) * 2; pos += 2;
			compressorName =  new String(header, pos, len, "UnicodeLittleUnmarked"); pos += len;
			len = GetAsShort(header, pos) * 2; pos += 2;
			compressorScheme =  new String(header, pos, len, "UnicodeLittleUnmarked"); pos += len;
			
			len = GetAsShort(header, pos) * 2; pos += 2;
			hashFunctionName =  new String(header, pos, len, "UnicodeLittleUnmarked"); pos += len;
			len = GetAsShort(header, pos) * 2; pos += 2;
			hashFunctionScheme =  new String(header, pos, len, "UnicodeLittleUnmarked"); pos += len;
			
			bHeaderAvailable = true;
			
			// Instantiate and setup components
			
			SetupComponents(cipherID, compressorID, hashFunctionID);
			
			cipherParams.SetKeySize(cipherParamBlock.cipherKeySize);
			cipherParams.SetBlockSize(cipherParamBlock.cipherBlockSize);
			cipherParams.SetRounds(cipherParamBlock.cipherRounds);
			cipherParams.SetScheme(cipherParamBlock.cipherScheme);
			cipherParams.SetChainingMode(cipherParamBlock.cipherMode);
			
			compressorParams.SetScheme(compressorParamBlock.compressorScheme);
			
			hashFunctionParams.SetHashSize(hashFunctionParamBlock.hashSize);
			hashFunctionParams.SetPasses(hashFunctionParamBlock.hashPasses);
			hashFunctionParams.SetScheme(hashFunctionParamBlock.hashScheme);
			
			// Get key
			
			bTestPasswordContext = true;
			if (keyRecord != null) keyRecord.clear();
			keyRecord = keyFunc.Callback(arg,
																	 cf.getName(),
																	 ExpectedKeyMaterial(keyMaterial),
																	 (keyMaterial.equals(KeyIdent.IDENT_PROTECTED_KEY)) ? keyAssociatedMaterial : keyMaterial);
			bTestPasswordContext = false;
			if (keyRecord == null) throw new UserAbortException();
	
			int keyLen;
			if (keyRecord == null) throw new UserAbortException();
			if (keyRecord.keyMaterial.equals(KeyIdent.IDENT_PASSWORD)
					|| keyRecord.keyMaterial.equals(KeyIdent.IDENT_LOWERCASE_PASSWORD)
					|| keyRecord.keyMaterial.equals(KeyIdent.IDENT_PROTECTED_KEY)) {
				ConvertPassword(keyRecord, hashFunctionComp);
				keyLen = hashFunctionParamBlock.hashSize;
			}
			else {
				assert ExpectedKeyMaterial(keyRecord.keyMaterial) == IKeyCallback.BINARY_KEY;
				keyLen = BINARY_KEY_SIZE;
			}
			
			if (keyRecord.keyMaterial.equals(KeyIdent.IDENT_PROTECTED_KEY)) {
				cipherParams.SetKey(keyRecord.keyData, 0, keyRecord.keyData.length);
				cipherParams.SetInitVector(Conversions.UuidToBytes(keyRecord.keyAssociatedMaterial), 0, 16);
				int cmode = cipherParams.GetChainingMode();
				cipherParams.SetChainingMode(IBlockCipherParams.MODE_CBC);
				blockCipher.Init();
				blockCipher.Encrypt(keyRecord.keyAssociatedData, 0, BINARY_KEY_SIZE);
				blockCipher.Done();
				cipherParams.SetChainingMode(cmode);
				
				cipherParams.SetKey(keyRecord.keyAssociatedData, 0, hashFunctionParamBlock.hashSize);
			}
			else
				cipherParams.SetKey(keyRecord.keyData, 0, hashFunctionParamBlock.hashSize);
			
			SetupHmac(keyRecord, keyLen);
			if (!Arrays.equals(keyVerificator, ComputeVerificator(verificationPasses))) throw new Exception(Message.Get(Message.Code.WrongKey));
	
			// Read agent data
			
			if (agentDataSize != 0) {
				agentData = new byte [agentDataSize];
				contFile.seek(agentDataPos);
				if (contFile.read(agentData) != agentDataSize) throw new Exception(Message.Get(Message.Code.InvalidContainer));
				if (!Arrays.equals(blockHmac.HashBlock(agentData, 0, agentDataSize), Arrays.copyOfRange(header, hdrAgentDataPos + 10, hdrAgentDataPos + 10 + hashFunctionParamBlock.hashSize))) throw new Exception(Message.Get(Message.Code.InvalidContainer));
			}
			else
				agentData = null;
			
			// Read directory
			
			initVector = new byte [cipherParamBlock.cipherBlockSize];
			rawCipher.EncryptBlock(initVector, 0, header, diriv);
			LoadDirectory(Arrays.copyOfRange(header, dirhm, dirhm + hashFunctionParamBlock.hashSize));
			
			if (GetAsShort(dirBuffer.Retrieve(2), 0) != OBJECT_START) throw new Exception(Message.Get(Message.Code.InvalidContainer));
			rootObject = new Object7(this, null, null);
			rootObject.LoadObject();
			
			assert contFile.getFilePointer() == (directoryPos + directorySize);
			
			// Loading fixup segments
			
			segmentStart = directoryPos + directorySize + headerSize + CONTAINER_TRAILER_SIZE + (ALIGNMENT_BOUNDARY - 1);
			segmentStart &= ~(ALIGNMENT_BOUNDARY - 1);
			if (fileSize < segmentStart) throw new Exception(Message.Get(Message.Code.InvalidContainerSize));

			statistics.uBaseSegmentSize = segmentStart;

			contFile.seek(segmentStart);
			
			segmentHeaderSize = (2 * 4 + 6 + hashFunctionParamBlock.hashSize + 6 + cipherParamBlock.cipherBlockSize + hashFunctionParamBlock.hashSize + 16);
			
			long lastSegmentStart;
			
			while (segmentStart < fileSize) {
				if (fileSize < (segmentStart + 4)) throw new Exception(Message.Get(Message.Code.InvalidContainerSize));
				contFile.read(ioBuffer, 0, 4);
				tag = GetAsInt(ioBuffer, 0);
				
				if (tag == FIXUP_IN_PROGRESS_TAG) {
					if (!IsReadOnly()) contFile.setLength(segmentStart);
					break;
				}
				
				else if (tag == FIXUP_TAG) {
					if (fileSize < (segmentStart + segmentHeaderSize + FIXUP_SEGMENT_TRAILER_SIZE)) throw new Exception(Message.Get(Message.Code.InvalidContainerSize));

					lastSegmentStart = segmentStart;
					statistics.nFixupSegments++;
					
					LoadSegment();
					
					segmentStart = contFile.getFilePointer() + FIXUP_SEGMENT_TRAILER_SIZE + (ALIGNMENT_BOUNDARY - 1);
					segmentStart &= ~(ALIGNMENT_BOUNDARY - 1);
					if (fileSize < segmentStart) throw new Exception(Message.Get(Message.Code.InvalidContainerSize));
					contFile.seek(segmentStart);
					
					statistics.uTotalFixupSegmentSize += segmentStart - lastSegmentStart;
				}
				
				else
					throw new Exception(Message.Get(Message.Code.InvalidContainer));
			}
			
			statistics.uDataAreaUnused = (statistics.uBaseDataAreaSize + statistics.uTotalFixupDataAreaSize) - (statistics.uDataAreaUsed + statistics.uTotalRecoveryBlockSize);
			
			if (!IsNewFileActive()) {
				nextDataPos = segmentStart;
				contMD5 = MessageDigest.getInstance("MD5");
			}

			bModified = false;
		}
		catch (Exception e) {
			Cleanup();
			throw e;
		}
		
		return rootObject;
	}
	
	
	public IEncryptedObject GetRootObject() {
		return IsOpen() ? rootObject : null;
	}
	
	
	public boolean IsModified() throws Exception {
		if (!IsOpen()) throw new Exception("Storage::IsModified : Container is not open.");
		return bModified;
	}
	
	
	public void Close() throws Exception {
		if (!IsOpen()) throw new Exception("Storage::Close : Container is not open.");
		if (bStreamActive) throw new Exception("Storage::Close : Container has an open stream.");
		
		if (BeingCompressed()) {
			Compress();
			return;
		}
		
		try {
			if (bModified) {
				assert !IsReadOnly();		// Sanity check

				if (IsNewFile())				// If new file, finalize base segment
					CloseNewFile();
				else										// Modifying existing file - create fixup segment
					CloseModifiedFile();
			}
			else		// If not modified
				contFile.close();
		}
		finally {
			Cleanup();
		}
	}
	
	
	public void Compress() throws Exception {
		if (!IsOpen()) throw new Exception("Storage::Compress : Container is not open.");
		if (IsReadOnly()) throw new Exception("Storage::Compress : Can't compress read-only container.");
		if (bStreamActive) throw new Exception("Storage::Compress : Container has an open stream.");

		
		if (IsNewFile() || (!bModified && statistics.nFixupSegments == 0 && statistics.uDataAreaUnused == 0 && !BeingCompressed())) {
			Close();
			return;
		}
		
		try {
			if (!IsNewFileActive()) CreateNewFile();		// Create new file if not created yet

			// Copy streams to the new file
			
			rootObject.MoveDataStreams();
			System.arraycopy(newMD5.digest(), 0, trailer, 34, 16);
				
			// Save agent data

			int asize = (agentData != null) ? agentData.length : 0;
			IntAsBytes(asize, header, hdrAgentDataPos);
			agentDataPos = nextDataPos;
			newFile.seek(agentDataPos);
			System.arraycopy(LongAsBytes(agentDataPos), 0, header, hdrAgentDataPos + 4, 6);
			System.arraycopy(header, hdrAgentDataPos + 4, trailer, 6, 6);
			if (agentData != null) {
				System.arraycopy(blockHmac.HashBlock(agentData, 0, agentData.length), 0, header, hdrAgentDataPos + 10, hashFunctionParamBlock.hashSize);
				newMD5.reset();
				System.arraycopy(newMD5.digest(agentData), 0, trailer, 50, 16);
				newFile.write(agentData, 0, agentData.length);
			}
			else {
				Arrays.fill(header, hdrAgentDataPos + 10, hdrAgentDataPos + 10 + hashFunctionParamBlock.hashSize, (byte)0);
				Arrays.fill(trailer, 50, 50 + 16, (byte)0);
			}
			nextDataPos += asize;
					
			// Save directory
			
			directoryPos = nextDataPos;
			hmacFunc.Init();
			newMD5.reset();
			
			try {
				cipherParams.SetInitVector(initVector, 0, cipherParamBlock.cipherBlockSize);
				compressorParams.SetLevel(CT_MAX_COMPRESSION);
				
				compressor.Init(new DirCompressSink(), null);
				rootObject.StoreObject();
				
				compressor.Done();
				System.arraycopy(hmacFunc.Done(), 0, header, hdrDirDataPos + 6 + cipherParamBlock.cipherBlockSize, hashFunctionParamBlock.hashSize);
				System.arraycopy(newMD5.digest(), 0, trailer, 66, 16);
			}
			catch (Exception e) {
				cipherState.Reset();
				compressorState.Reset();
				throw e;
			}

			nextDataPos = newFile.getFilePointer();
			long dirSize = nextDataPos - directoryPos;
			System.arraycopy(LongAsBytes(dirSize), 0, header, hdrDirDataPos, 6);
			System.arraycopy(header, hdrDirDataPos, trailer, 12, 6);

			// Header is complete - compute its MD5 checksum and write both copies
			newMD5.reset();
			newMD5.update(header, 0, header.length - 16);
			newMD5.digest(header, header.length - 16, 16);
			newFile.seek(0);
			newFile.write(header, 0, header.length);
			newFile.seek(nextDataPos);
			newFile.write(header, 0, header.length);
					
			// Complete trailer and write it
			IntAsBytes(TRAILER_TAG, trailer, 0);
			IntAsBytes(header.length, trailer, 4);
			System.arraycopy(header, header.length - 16, trailer, 18, 16);
			
			newMD5.reset();
			newMD5.update(trailer, 0, CONTAINER_TRAILER_SIZE - 16);
			newMD5.digest(trailer, CONTAINER_TRAILER_SIZE - 16, 16);
			newFile.write(trailer, 0, CONTAINER_TRAILER_SIZE);
					
			WriteAlignmentData();
					
			newFile.close();
	
			// New file is complete, now rename it and delete old one
	
			contFile.close();
			File cf = new File(contPath);
			cf.delete();
			File nf = new File(newPath);
			nf.renameTo(cf);
		}
		catch (Exception e) {
			if (IsNewFileActive()) {
				newFile.close();
				File nf = new File(newPath);
				nf.delete();
			}
			throw e;
		}
		finally {
			Cleanup();
		}
	}
	
	
	public void Discard() throws Exception {
		if (!IsOpen()) throw new Exception("Storage::Discard : Container is not open.");
		if (bStreamActive) throw new Exception("Storage::Discard : Container has an open stream.");
		
		try {
			if (bModified) {
				assert !IsReadOnly();			// Sanity check
				if (contFile != null) {		// Discard the current fixup segment
					contFile.setLength(segmentStart);
					contFile.close();
				}
			}
			else		// If not modified
				contFile.close();

			if (IsNewFileActive()) {					// If new file, delete it
				newFile.close();
				File nf = new File(newPath);
				nf.delete();
			}
		}
		finally {
			Cleanup();
		}
	}
	
	
  //
  // Private data and methods
  //
	
	
  static long componentType = TYPE_STORAGE_HANDLER;
  static UUID componentID = CID_STORAGE_7;

  private static short CONT_CUR_VERSION							= 0x0200;
  private static short CONT_REQ_VERSION							= 0x0100;
  private static short CONT_REQ_KEYPROT_VERSION			= 0x010C;
  
  private static int MIN_HEADER_SIZE = 200;			// Very approximate value for first validity check during open
  
	private long compCapabilities = CAP_DEFAULT_CAPABILITIES;
	
	final byte[] ioBuffer = new byte [DEFAULT_BUFFER_SIZE];
	
	private CONTAINER_ACCESS_MODE contMode;
	RandomAccessFile contFile;
	RandomAccessFile newFile;
	String contPath;
	String newPath;
	
	long nextDataPos;
	
	boolean bHeaderAvailable;
	private byte[] header;
	private int hdrAgentDataPos;
	private int hdrDirDataPos;
	
	private byte[] trailer = new byte [Math.max(CONTAINER_TRAILER_SIZE, FIXUP_SEGMENT_TRAILER_SIZE)];
	
	boolean bReadOnly = false;
	boolean bModified = false;
	boolean bStreamActive = false;
	
	MessageDigest contMD5;
	MessageDigest newMD5;
	
	private StorageInfo storageInfo;
	StorageStatistics statistics;
	
	Object7 rootObject;
	
	private UUID contAgent;
	private byte[] agentData;
	private boolean agentDataUpdated = false;
	private long agentDataPos;
	private int agentDataSize;
	
	private long directoryPos;
	private long directorySize;
	SmartBuffer dirBuffer = new SmartBuffer();
	byte[] dirHmac;
	
	private byte[] initVector;
	
	private long segmentStart;
	private int segmentHeaderSize;
	
	private CONTAINER_COMPRESSION_STRATEGY compressionStrategy = DEFAULT_COMPRESSION_STRATEGY;
	
	private KeyRecord keyRecord;
	private UUID keyMaterial;
	private UUID keyAssociatedMaterial;
	private boolean bTestPasswordContext = false;
	private int verificationPasses;
	private byte[] keyVerificator;
	private byte[] keyAssocDataCopy;

	FixupObject7 fixupList, fixupListTail;
	
	//
	// Components used
	//
	
	SecureRandom rand;
	
	IKryptelComponent cipherComp;
	IComponentState cipherState;
	IBlockCipherParams cipherParams;
	IRawBlockCipher rawCipher;
	IBlockCipher blockCipher;
	ICipher cipher;
	
	IKryptelComponent compressorComp;
	IComponentState compressorState;
	ICompressorParams compressorParams;
	ICompressor compressor;
	
	IKryptelComponent hashFunctionComp;
	IComponentState hashFunctionState;
	IHashFunctionParams hashFunctionParams;
	IMemoryBlockHash blockHashFunction;
	IHashFunction hashFunction;
	
	IKryptelComponent hmacComp;
	IComponentState hmacState;
	IMacSetup hmacSetup;
	IHashFunctionParams hmacParams;
	IMemoryBlockHash blockHmac;
	IHashFunction hmacFunc;
	
	//
	// Info about used components
	// 'Create' fills these fields from components
	// 'Open' reads them from the container header so these data
	// are valid even if the components are not instantiated yet.
	//
	
	UUID cipherID;
	String cipherName;
	String cipherScheme;
	CipherParameters cipherParamBlock;
	
	UUID compressorID;
	String compressorName;
	String compressorScheme;
	CompressorParameters compressorParamBlock;
	
	UUID hashFunctionID;
	String hashFunctionName;
	String hashFunctionScheme;
	HashFunctionParameters hashFunctionParamBlock;

	
	//
	// Private methods
	//
	
	boolean IsOpen() { return contFile != null || newFile != null; }
	boolean IsReadOnly() { return bReadOnly; }
	boolean IsNewFileActive() { return newFile != null; }
	boolean IsNewFile() { return contFile == null && newFile != null; }
	boolean BeingCompressed() { return contFile != null && newFile != null; }

	
	void SetModified() throws Exception {
		if (!bModified && !IsNewFileActive()) {		// Start fixup segment
			assert (!IsNewFile());
			assert (!IsReadOnly());
			
			contFile.seek(segmentStart);
			
			int tag = FIXUP_IN_PROGRESS_TAG;
			contFile.write(IntAsBytes(tag));
			
			nextDataPos = segmentStart + segmentHeaderSize;
			contFile.seek(nextDataPos);
		}
		bModified = true;
	}

	
	private void Cleanup() throws Exception {
		if (cipherComp != null) {
			if (cipherState.GetState() == ComponentState.ComponentBusy) cipherState.Reset();
			cipherComp.DiscardComponent();
			cipherComp = null;
		}
		if (compressorComp != null) {
			if (compressorState.GetState() == ComponentState.ComponentBusy) compressorState.Reset();
			compressorComp.DiscardComponent();
			compressorComp = null;
		}
		if (hashFunctionComp != null) {
			if (hashFunctionState.GetState() == ComponentState.ComponentBusy) hashFunctionState.Reset();
			hashFunctionComp.DiscardComponent();
			hashFunctionComp = null;
		}
		if (hmacComp != null) {
			if (hmacState.GetState() == ComponentState.ComponentBusy) hmacState.Reset();
			hmacComp.DiscardComponent();
			hmacComp = null;
		}
		if (keyRecord != null) {
			keyRecord.clear();
			keyRecord = null;
		}
		if (keyAssocDataCopy != null) {
			Arrays.fill(keyAssocDataCopy, (byte)0);
			keyAssocDataCopy = null;
		}
		if (initVector != null) {
			Arrays.fill(initVector, (byte)0);
			initVector = null;
		}
		if (contFile != null) {
			contFile.close();
			contFile = null;
		}
		if (newFile != null) {
			newFile.close();
			newFile = null;
		}
		
		statistics = null;
		rootObject = null;
		agentData = null;
		keyVerificator = null;
		dirHmac = null;
		header = null;
		bHeaderAvailable = false;
		bStreamActive = false;;
		dirBuffer.Empty();
		storageInfo = null;
		
		fixupList = null;
		fixupListTail = null;
	}
	
	
	private void SetupHmac(KeyRecord keyRecord, int keyLen) throws Exception {
		assert (keyRecord.keyData.length >= keyLen && keyLen > 0 && keyLen <= BINARY_KEY_SIZE);
		byte[] hmacKey = new byte [BINARY_KEY_SIZE];
		Arrays.fill(hmacKey, (byte)0);
		for (int i = 0, j = keyLen; i < keyLen; ) hmacKey[i++] = (byte)(~keyRecord.keyData[--j]);
		hmacSetup.SetKey(hmacKey, 0, 512 / 8);
	}
	
	
	private byte[] ComputeVerificator(int nCounts) throws Exception {
		byte[] keyVerificator = new byte [hmacParams.GetHashSize()];

		int[] verArray = new int [nCounts];
		byte[] verBytes = new byte [nCounts * 4];
		
		for (int i = 0; i < nCounts; i++) {
			verArray[i] = i;
			Conversions.ToBytes(verBytes, 0, verArray, 0, (i + 1) * 4);
			hmacFunc.Init();
			hmacFunc.Hash(verBytes, 0, (i + 1) * 4);
			hmacFunc.Hash(keyVerificator, 0, keyVerificator.length);
			keyVerificator = hmacFunc.Done();
		}
		return keyVerificator;
	}
	
	
	private void SetupComponents(UUID cipher, UUID compressor, UUID hashFunc) throws Exception {
		SetupComponents(Loader.CreateComponent(cipher, compCapabilities),
										Loader.CreateComponent(compressor, compCapabilities),
										Loader.CreateComponent(hashFunc, compCapabilities));
	}
	
	private void SetupComponents(IKryptelComponent cipher, IKryptelComponent compressor, IKryptelComponent hashFunc) throws Exception {
		if (cipher == null) throw new Exception("Storage : No such cipher.");
		if ((cipher.ComponentType() & TYPE_BLOCK_CIPHER) == 0) throw new Exception("Storage : Invalid cipher.");
		IComponentState cs = (IComponentState)cipher.GetInterface(IID_IComponentState);
		cipherComp = cs.Clone();
		cipherState = (IComponentState)cipherComp.GetInterface(IID_IComponentState);
		cipherParams = (IBlockCipherParams)cipherComp.GetInterface(IID_IBlockCipherParams);
		rawCipher = (IRawBlockCipher)cipherComp.GetInterface(IID_IRawBlockCipher);
		blockCipher = (IBlockCipher)cipherComp.GetInterface(IID_IBlockCipher);
		this.cipher = (ICipher)cipherComp.GetInterface(IID_ICipher);
		assert cipherState != null && cipherParams != null && rawCipher != null && blockCipher != null && this.cipher != null;
		
		if (compressor == null) throw new Exception("Storage : No such compressor.");
		if ((compressor.ComponentType() & TYPE_COMPRESSOR) == 0) throw new Exception("Storage : Invalid compressor.");
		cs = (IComponentState)compressor.GetInterface(IID_IComponentState);
		compressorComp = cs.Clone();
		compressorState = (IComponentState)compressorComp.GetInterface(IID_IComponentState);
		compressorParams = (ICompressorParams)compressorComp.GetInterface(IID_ICompressorParams);
		this.compressor = (ICompressor)compressorComp.GetInterface(IID_ICompressor);
		assert compressorState != null && compressorParams != null && this.compressor != null;

		if (hashFunc == null) throw new Exception("Storage : No such hash function.");
		if ((hashFunc.ComponentType() & TYPE_HASH_FUNCTION) == 0) throw new Exception("Storage : Invalid hash function.");
		cs = (IComponentState)hashFunc.GetInterface(IID_IComponentState);
		hashFunctionComp = cs.Clone();
		hashFunctionState = (IComponentState)hashFunctionComp.GetInterface(IID_IComponentState);
		hashFunctionParams = (IHashFunctionParams)hashFunctionComp.GetInterface(IID_IHashFunctionParams);
		blockHashFunction = (IMemoryBlockHash)hashFunctionComp.GetInterface(IID_IMemoryBlockHash);
		hashFunction = (IHashFunction)hashFunctionComp.GetInterface(IID_IHashFunction);
		assert hashFunctionState != null && hashFunctionParams != null && blockHashFunction != null && hashFunction != null;

		hmacComp = (IKryptelComponent)Loader.CreateComponent(CID_HMAC);
		hmacState = (IComponentState)hmacComp.GetInterface(IID_IComponentState);
		hmacSetup = (IMacSetup)hmacComp.GetInterface(IID_IMacSetup);
		assert hmacSetup != null;
		hmacSetup.SetBase(hashFunctionComp);
		hmacParams = (IHashFunctionParams)hmacComp.GetInterface(IID_IHashFunctionParams);
		blockHmac = (IMemoryBlockHash)hmacComp.GetInterface(IID_IMemoryBlockHash);
		hmacFunc = (IHashFunction)hmacComp.GetInterface(IID_IHashFunction);
		assert hmacParams != null && blockHmac != null && hmacFunc != null;
	}
	
	
	private void BuildHeader() throws Exception {
		SmartBuffer sbuf = new SmartBuffer();
		
		sbuf.Store(ShortAsBytes(CONT_CUR_VERSION));
		sbuf.Store(ShortAsBytes((keyRecord.keyMaterial.equals(KeyIdent.IDENT_PROTECTED_KEY)) ? CONT_REQ_KEYPROT_VERSION : CONT_REQ_VERSION));
		
		sbuf.Store(UuidToBytes(componentID));
		sbuf.Store(UuidToBytes(contAgent));
		sbuf.Store(UuidToBytes(cipherID));
		sbuf.Store(UuidToBytes(compressorID));
		sbuf.Store(UuidToBytes(hashFunctionID));
		
		sbuf.Store(IntAsBytes(cipherParamBlock.cipherKeySize));
		sbuf.Store(IntAsBytes(cipherParamBlock.cipherBlockSize));
		sbuf.Store(IntAsBytes(cipherParamBlock.cipherRounds));
		sbuf.Store(IntAsBytes(cipherParamBlock.cipherScheme));
		sbuf.Store(IntAsBytes(cipherParamBlock.cipherMode));
		
		sbuf.Store(IntAsBytes(compressorParamBlock.compressorScheme));
		
		sbuf.Store(IntAsBytes(hashFunctionParamBlock.hashSize));
		sbuf.Store(IntAsBytes(hashFunctionParamBlock.hashPasses));
		sbuf.Store(IntAsBytes(hashFunctionParamBlock.hashScheme));
		
		sbuf.Store(UuidToBytes(keyRecord.keyMaterial));
		if (keyAssocDataCopy != null) {		// Saved associated data present (probably compressing existing container)
			sbuf.Store(ShortAsBytes((short)keyAssocDataCopy.length));
			sbuf.Store(keyAssocDataCopy);
		}
		else if (keyRecord.keyMaterial.equals(KeyIdent.IDENT_PROTECTED_KEY)) {
			sbuf.Store(ShortAsBytes((short)16));
			sbuf.Store(UuidToBytes(keyRecord.keyAssociatedMaterial));
		}
		else		// No associated data
			sbuf.Store(ShortAsBytes((short)0));
		sbuf.Store(IntAsBytes(verificationPasses));
		sbuf.Store(keyVerificator);
		
		// Nothing is known about agent data yet, just save the header position
		hdrAgentDataPos = 4 + 2 + sbuf.Size();		// Two first fields will be added later
		byte[] dummy = new byte [4 + 6 + hashFunctionParamBlock.hashSize];
		sbuf.Store(dummy);
		
		// Directory
		hdrDirDataPos = 4 + 2 + sbuf.Size();		// Two first fields will be added later
		sbuf.Store(dummy, 0, 6);								// Skip directory size field
		byte[] iv = new byte [cipherParamBlock.cipherBlockSize];
		rawCipher.DecryptBlock(iv, 0, initVector, 0);
		sbuf.Store(iv);
		sbuf.Store(dummy, 0, hashFunctionParamBlock.hashSize);	// Skip directory HMAC field
		
		// Store strings
		sbuf.Store(ShortAsBytes((short)cipherName.length())); sbuf.Store(cipherName.getBytes("UnicodeLittleUnmarked"));
		sbuf.Store(ShortAsBytes((short)cipherScheme.length())); sbuf.Store(cipherScheme.getBytes("UnicodeLittleUnmarked"));
		sbuf.Store(ShortAsBytes((short)compressorName.length())); sbuf.Store(compressorName.getBytes("UnicodeLittleUnmarked"));
		sbuf.Store(ShortAsBytes((short)compressorScheme.length())); sbuf.Store(compressorScheme.getBytes("UnicodeLittleUnmarked"));
		sbuf.Store(ShortAsBytes((short)hashFunctionName.length())); sbuf.Store(hashFunctionName.getBytes("UnicodeLittleUnmarked"));
		sbuf.Store(ShortAsBytes((short)hashFunctionScheme.length())); sbuf.Store(hashFunctionScheme.getBytes("UnicodeLittleUnmarked"));

		int headerSize = sbuf.Size() + 4 + 2 + 16;			// buffer size + two first fields + MD5 hash
		sbuf.Unretrieve(ShortAsBytes((short)headerSize), 0, 2);	// Push header size
		sbuf.Unretrieve(IntAsBytes(CONTAINER_TAG), 0, 4);
		header = new byte [headerSize];
		sbuf.Retrieve(header, 0, headerSize);
	}
	
	
	private void CreateNewFile() throws Exception {
		newPath = contPath + ".tmp";
		int cnt = 2;
		while ((new File(newPath)).exists())
			newPath = contPath + String.format(".%d", cnt++) + ".tmp";
		
		if (header == null) BuildHeader();
		
		newFile = new RandomAccessFile(newPath, "rw");
		newFile.seek(header.length);
		
		nextDataPos = header.length;
		newMD5 = MessageDigest.getInstance("MD5");
	}
	
	
	private void LoadDirectory(byte[] hmac) throws Exception {
		contFile.seek(directoryPos);
		cipherParams.SetInitVector(initVector, 0, cipherParamBlock.cipherBlockSize);
		cipher.Init(new DirDecryptSink(), null);

		long dirsize = directorySize;
		int len;
		
		while (dirsize > 0) {
			len = (int)Math.min(dirsize, ioBuffer.length);
			contFile.read(ioBuffer, 0, len);
			cipher.Decrypt(ioBuffer, 0, len);
			dirsize -= len;
		}

		cipher.Done();
		if (!Arrays.equals(hmac, dirHmac)) throw new Exception(Message.Get(Message.Code.InvalidContainer));
	}
	
	
	private void LoadSegment() throws Exception {
		assert rootObject != null;		// Assert that the main directory has been loaded successfully
		
		// Load header
		
		byte[] segmentHeader = new byte [segmentHeaderSize];

		contFile.seek(segmentStart);
		contFile.read(segmentHeader);
		
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		md5.update(segmentHeader, 0, segmentHeaderSize - 16);
		if (!Arrays.equals(md5.digest(), Arrays.copyOfRange(segmentHeader, segmentHeaderSize - 16, segmentHeaderSize))) throw new Exception(Message.Get(Message.Code.InvalidContainer));
		
		// Load agent data
		
		int agentDataSize = GetAsInt(segmentHeader, 4);
		agentDataPos = GetAsLong(segmentHeader, 8);
		agentDataPos &= 0x0000FFFFFFFFFFFFL;

		statistics.uTotalFixupDataAreaSize += agentDataPos - (segmentStart + segmentHeaderSize);
		
		contFile.seek(agentDataPos);
		
		if (agentDataSize == REMOVE_AGENT_DATA) {
			assert agentData != null && agentDataSize > 0;
			agentData = null;
			agentDataSize = 0;
			
			statistics.uAgentDataSize = 0;
		}
		else if (agentDataSize != NO_AGENT_DATA) {
			agentData = new byte [agentDataSize];
			contFile.read(agentData);
			if (!Arrays.equals(blockHmac.HashBlock(agentData, 0, agentDataSize), Arrays.copyOfRange(segmentHeader, 14, hashFunctionParamBlock.hashSize))) throw new Exception(Message.Get(Message.Code.InvalidContainer));
			
			statistics.uAgentDataSize = agentDataSize;
		}
		
		// Load fixup list

		long fixupListSize = GetAsLong(segmentHeader, 14 + hashFunctionParamBlock.hashSize);
		fixupListSize &= 0x0000FFFFFFFFFFFFL;

		statistics.uTotalFixupListSize += fixupListSize;
		
		if (fixupListSize > 0) {
			byte[] fxInitVector = new byte [cipherParamBlock.cipherBlockSize];
			rawCipher.EncryptBlock(fxInitVector, 0, segmentHeader, 20 + hashFunctionParamBlock.hashSize);
			
			// Read and decrypt fixup list
			
 			cipherParams.SetInitVector(fxInitVector, 0, cipherParamBlock.cipherBlockSize);
			cipher.Init(new DirDecryptSink(), null);

			long flsize = fixupListSize;
			int len;
			
			while (flsize > 0) {
				len = (int)Math.min(flsize, ioBuffer.length);
				contFile.read(ioBuffer, 0, len);
				cipher.Decrypt(ioBuffer, 0, len);
				flsize -= len;
			}
			cipher.Done();
			
			// Fixup list has been decrypted into dirBuffer, now parse it
			
			Object7 obj;
			short tag, nGuids;
			UUID[] uidPath = new UUID [64];		// Tree depth 64 must be more than enough

			while (dirBuffer.Size() > 0) {
				statistics.nFixupRecords++;
				
				if (dirBuffer.Size() < 4) throw new Exception(Message.Get(Message.Code.InvalidContainer));
				tag = GetAsShort(dirBuffer.Retrieve(2), 0);
				nGuids = GetAsShort(dirBuffer.Retrieve(2), 0);
				if (dirBuffer.Size() < (nGuids * 16)) throw new Exception(Message.Get(Message.Code.InvalidContainer));
				
				if (tag == FIXUP_RECORD_ADD_OBJECT || tag == FIXUP_RECORD_CREATE_OBJECT) {
					if (nGuids > 1) {
						if (uidPath.length < nGuids) uidPath = new UUID [nGuids];
						for (int i = 0; i < (nGuids - 1); i++) uidPath[i] = UuidFromBytes(dirBuffer.Retrieve(16), 0);
						obj = rootObject.LocateChild(uidPath, 0, nGuids - 1);
						obj.LoadChildFromFixup(tag);
					}
					else
						rootObject.LoadChildFromFixup(tag);
				}
				else {		// Modifying existing object
					if (uidPath.length < nGuids) uidPath = new UUID [nGuids];
					for (int i = 0; i < nGuids; i++) uidPath[i] = UuidFromBytes(dirBuffer.Retrieve(16), 0);
					obj = rootObject.LocateChild(uidPath, 0, nGuids);
					assert !obj.IsDeleted();

					if (tag == FIXUP_RECORD_ATTACH_ATTRIBUTES)
						obj.LoadAttributes();

					else if (tag == FIXUP_RECORD_ATTACH_DATA)
						obj.LoadStream();

					else if (tag == FIXUP_RECORD_MOVE_OBJECT) {
						if (dirBuffer.Size() < 2) throw new Exception(Message.Get(Message.Code.InvalidContainer));
						nGuids = GetAsShort(dirBuffer.Retrieve(2), 0);
						if (dirBuffer.Size() < (nGuids * 16)) throw new Exception(Message.Get(Message.Code.InvalidContainer));
						if (uidPath.length < nGuids) uidPath = new UUID [nGuids];
						for (int i = 0; i < (nGuids - 1); i++) uidPath[i] = UuidFromBytes(dirBuffer.Retrieve(16), 0);
						
						Object7 target = rootObject.LocateChild(uidPath, 0, nGuids - 1);
						assert !target.IsDeleted();
						obj.MoveMe(target);
					}

					else if (tag == FIXUP_RECORD_DELETE_OBJECT)
						obj.MarkAsDeleted();

					else if (tag == FIXUP_RECORD_UNDELETE_OBJECT) {
						if (dirBuffer.Size() < 1) throw new Exception(Message.Get(Message.Code.InvalidContainer));
						obj.UnmarkAsDeleted(dirBuffer.Retrieve(1)[0] != 0);
					}

					else
						throw new Exception(Message.Get(Message.Code.InvalidContainer));
				}
			}
		}
	}
	
	
	void CloseNewFile() throws Exception {
		assert IsNewFile();

		newFile.seek(nextDataPos);

		newMD5.digest(trailer, 34, 16);		// Data area hash
		
		// Save agent data
		if (agentData == null) agentDataSize = 0;
		IntAsBytes(agentDataSize, header, hdrAgentDataPos);
		agentDataPos = nextDataPos;
		System.arraycopy(LongAsBytes(agentDataPos), 0, header, hdrAgentDataPos + 4, 6);
		System.arraycopy(header, hdrAgentDataPos + 4, trailer, 6, 6);
		
		
		if (agentDataSize > 0) {
			System.arraycopy(blockHmac.HashBlock(agentData, 0, agentDataSize), 0, header, hdrAgentDataPos + 10, hashFunctionParamBlock.hashSize);
			System.arraycopy(newMD5.digest(agentData), 0, trailer, 50, 16);
			newFile.write(agentData);
		}
		else {
			Arrays.fill(header, hdrAgentDataPos + 10, hdrAgentDataPos + 10 + hashFunctionParamBlock.hashSize, (byte)0);
			Arrays.fill(trailer, 50, 66, (byte)0);
		}
		nextDataPos += agentDataSize;
		
		// Save directory
		long dirStart = nextDataPos;
		hmacFunc.Init();
		newMD5.reset();

		try {
			cipherParams.SetInitVector(initVector, 0, cipherParamBlock.cipherBlockSize);
			compressorParams.SetLevel(CT_MAX_COMPRESSION);
			
			compressor.Init(new DirCompressSink(), null);
			rootObject.StoreObject();
			
			compressor.Done();
			System.arraycopy(hmacFunc.Done(), 0, header, hdrDirDataPos + 6 + cipherParamBlock.cipherBlockSize, hashFunctionParamBlock.hashSize);
			newMD5.digest(trailer, 66, 16);
		}
		catch (Exception e) {
			cipherState.Reset();
			compressorState.Reset();
			throw e;
		}

		long dirSize = nextDataPos - dirStart;
		System.arraycopy(LongAsBytes(dirSize), 0, header, hdrDirDataPos, 6);
		System.arraycopy(header, hdrDirDataPos, trailer, 12, 6);

		// Header is complete - compute its MD5 checksum and write both copies
		newMD5.reset();
		newMD5.update(header, 0, header.length - 16);
		newMD5.digest(header, header.length - 16, 16);
		newFile.seek(0);
		newFile.write(header);
		newFile.seek(nextDataPos);
		newFile.write(header);
		
		// Complete trailer and write it
		IntAsBytes(TRAILER_TAG, trailer, 0);
		ShortAsBytes((short)header.length, trailer, 4);
		newMD5.reset();
		newMD5.update(header, 0, header.length);
		newMD5.digest(trailer, 18, 16);
		
		newMD5.reset();
		newMD5.update(trailer, 0, CONTAINER_TRAILER_SIZE - 16);
		newMD5.digest(trailer, CONTAINER_TRAILER_SIZE - 16, 16);
		newFile.write(trailer, 0, CONTAINER_TRAILER_SIZE);
		
		WriteAlignmentData();
		
		// Close and rename file
		newFile.close();
		File cf = new File(contPath);
		File nf = new File(newPath);
		if (!nf.renameTo(cf)) throw new Exception("Storage::CloseNewFile : File rename operation failed.");
	}


	void WriteAlignmentData() throws Exception {
		boolean bNewFile = IsNewFileActive();
		long uSegmentEnd = bNewFile ? newFile.getFilePointer() : contFile.getFilePointer();
		long uFileEnd = uSegmentEnd + (ALIGNMENT_BOUNDARY - 1);
		uFileEnd &= ~(ALIGNMENT_BOUNDARY - 1);
		int uAlignmentSize = (int)(uFileEnd - uSegmentEnd);
		
		byte[] fillData = new byte [ALIGNMENT_BOUNDARY];
		for (int i = 0; i < fillData.length; i += 2) {
			fillData[i] = (byte)0xED;
			fillData[i + 1] = (byte)0xC7;
		}
		
		if (bNewFile)
			newFile.write(fillData, ALIGNMENT_BOUNDARY - uAlignmentSize, uAlignmentSize);
		else
			contFile.write(fillData, ALIGNMENT_BOUNDARY - uAlignmentSize, uAlignmentSize);
	}

	
	void CloseModifiedFile() throws Exception {
		assert !IsNewFileActive();
		
		contFile.seek(nextDataPos);

		ReduceFixupList();		// Reducing may produce empty list so we need to reduce first

		if (agentDataUpdated || fixupList != null) {
			IntAsBytes(FIXUP_TRAILER_TAG, trailer, 0);
			LongAsBytes(segmentStart, trailer, 4);
			
			System.arraycopy(contMD5.digest(), 0, trailer, 38, 16);		// Data area hash
			
			header = new byte [segmentHeaderSize];
			IntAsBytes(FIXUP_TAG, header, 0);
			
			// Save agent data
			
			agentDataPos = nextDataPos;
			LongAsBytes(agentDataPos, header, 8);
			System.arraycopy(header, 8, trailer, 10, 6);
			
			Arrays.fill(header, 14, 14 + hashFunctionParamBlock.hashSize, (byte)0);		// Agent data HMAC
			Arrays.fill(trailer, 54, 54 + 16, (byte)0);																// Segment header MD5 hash

			if (agentDataUpdated) {
				if (agentData != null) {
					IntAsBytes(agentData.length, header, 4);
					System.arraycopy(blockHmac.HashBlock(agentData, 0, agentData.length), 0, header, 14, hashFunctionParamBlock.hashSize);
					contMD5.reset();
					System.arraycopy(contMD5.digest(agentData), 0, trailer, 14, 16);
					contFile.write(agentData);
					nextDataPos += agentData.length;
				}
				else
					IntAsBytes(REMOVE_AGENT_DATA, header, 4);
			}
			else
				IntAsBytes(NO_AGENT_DATA, header, 4);
			
			// Save fixup list
			
			if (fixupList != null) {
				long fixupListStart = nextDataPos;
				
				hmacFunc.Init();
				contMD5.reset();

				assert initVector != null;		// It must still contain the main dir init vector - discard it
				rand.nextBytes(initVector);		// Create a new init vector for fixup list

				try {
					cipherParams.SetInitVector(initVector, 0, cipherParamBlock.cipherBlockSize);
					compressorParams.SetLevel(CT_MAX_COMPRESSION);
					
					compressor.Init(new DirCompressSink(), null);

					StoreFixupList();
					
					compressor.Done();
					System.arraycopy(hmacFunc.Done(), 0, header, 14 + hashFunctionParamBlock.hashSize + 6 + cipherParamBlock.cipherBlockSize, hashFunctionParamBlock.hashSize);
					System.arraycopy(contMD5.digest(), 0, trailer, 70, 16);
				}
				catch (Exception e) {
					cipherState.Reset();
					compressorState.Reset();
					throw e;
				}
				
				long fixupListSize = contFile.getFilePointer() - fixupListStart;
				System.arraycopy(LongAsBytes(fixupListSize), 0, header, 14 + hashFunctionParamBlock.hashSize, 6);
				System.arraycopy(LongAsBytes(fixupListStart), 0, trailer, 16, 6);
				rawCipher.DecryptBlock(header, 14 + hashFunctionParamBlock.hashSize + 6, initVector, 0);
			}
			else {		// Empty fixup list
				System.arraycopy(LongAsBytes(agentDataPos), 0, trailer, 16, 6);
				Arrays.fill(header, 14 + hashFunctionParamBlock.hashSize, 14 + hashFunctionParamBlock.hashSize + 6 + cipherParamBlock.cipherBlockSize + hashFunctionParamBlock.hashSize, (byte)0);
				Arrays.fill(trailer, 70, 70 + 16, (byte)0);
			}
			
			// Header is now complete - compute its MD5 checksum
			contMD5.reset();
			contMD5.update(header, 0, segmentHeaderSize - 16);
			contMD5.digest(header, segmentHeaderSize - 16, 16);
			
			// Finalize and write segment trailer
			System.arraycopy(header, segmentHeaderSize - 16, trailer, 22, 16);

			contMD5.reset();
			contMD5.update(trailer, 0, FIXUP_SEGMENT_TRAILER_SIZE - 16);
			contMD5.digest(trailer, FIXUP_SEGMENT_TRAILER_SIZE - 16, 16);
			contFile.write(trailer, 0, FIXUP_SEGMENT_TRAILER_SIZE);

			WriteAlignmentData();

			// Writing the header must be the last operation
			contFile.seek(segmentStart);
			contFile.write(header, 0, segmentHeaderSize);
			contFile.close();
		}
		else {		// File has been modified, but all the modifications have been undone - discard the current fixup segment
			contFile.setLength(segmentStart);
			contFile.close();
		}
	}
	
	
	//
	// Compression occurs if
	//
	//  U > U_0 AND S_total > S_0 AND S_used < D_max
	//
	// where
	//  U = (S_unused * 100) / S_total			- unused space in percents
	//
	//  U_0		- unused space threshold
	//  S_0		- minimal size of data area (too small files are not compressed no matter how badly its space is used)
	//  D_max	- max size to copy (if compression will take too long, don't do it automatically)
	//
	// The above constants specified separately for fixed and removable drives
	//
	
	private static final int U_0							= 35;
	private static final long S_0							= (5 * 1024 * 1024L);				// 5Mb
	private static final long D_max						= (500 * 1024 * 1024L);			// 500Mb

	void CheckIfCompressionNeeded() throws Exception {
		
		if (IsNewFileActive() || IsReadOnly() || statistics.uDataAreaUnused == 0) return;
		
		if (compressionStrategy == CONTAINER_COMPRESSION_STRATEGY.KRCONT_COMPRESS_NEVER) return;
		
		if (compressionStrategy == CONTAINER_COMPRESSION_STRATEGY.KRCONT_COMPRESS_ALWAYS) {
			CreateNewFile();
			return;
		}
		
		// Smart compression
		
		assert compressionStrategy == CONTAINER_COMPRESSION_STRATEGY.KRCONT_COMPRESS_SMART;
		
		long S_total = statistics.uDataAreaUsed + statistics.uDataAreaUnused;
		assert S_total != 0;
		int U = (int)((statistics.uDataAreaUnused * 100) / S_total);
		
		if (U > U_0 &&
				S_total > S_0 &&
				statistics.uDataAreaUsed < D_max)
			CreateNewFile();
	}


	void ReduceFixupList() {
		FixupObject7 p = fixupList;
		while (p != null) p = p.Reduce();
	}
	
	
	void StoreFixupList() throws Exception {
		FixupObject7 p = fixupList;
		while (p != null) {
			p.Store();
			p = p.next;
		}
	}
	
	
	//
	// Sinks
	//
	
	private class DirDecryptSink implements IDataSink {
		public void Init(Object arg) throws Exception {
			compressor.Init(new DirDecompressSink(), arg);
		}

		public void PutData(byte[] buf, int start, int size) throws Exception {
			compressor.Decompress(buf, start, size);
		}

		public void Done() throws Exception {
			compressor.Done();
		}
	}
	
	private class DirDecompressSink implements IDataSink {
		public void Init(Object arg) throws Exception {
			dirBuffer.Empty();
			hmacFunc.Init();
		}

		public void PutData(byte[] buf, int start, int size) throws Exception {
			hmacFunc.Hash(buf, start, size);
			dirBuffer.Store(buf, start, size);
		}

		public void Done() throws Exception {
			dirHmac = hmacFunc.Done();
		}
	}
	
	private class DirEncryptSink implements IDataSink {
		public void Init(Object arg) throws Exception {
		}

		public void PutData(byte[] buf, int start, int size) throws Exception {
			if (IsNewFileActive()) {
				newMD5.update(buf, start, size);
				newFile.write(buf, start, size);
			}
			else {
				contMD5.update(buf, start, size);
				contFile.write(buf, start, size);
			}
			nextDataPos += size;
		}

		public void Done() throws Exception {
		}
	}
	
	private class DirCompressSink implements IDataSink {
		public void Init(Object arg) throws Exception {
			cipher.Init(new DirEncryptSink(), arg);
		}

		public void PutData(byte[] buf, int start, int size) throws Exception {
			cipher.Encrypt(buf, start, size);
		}

		public void Done() throws Exception {
			cipher.Done();
		}
	}

	
	//
	// IEncryptedStorageInfo
	//

	
	private class StorageInfo implements IEncryptedStorageInfo {
		public int GetStorageCapabilities() {
			if (IsOpen() && IsReadOnly())
				return	ESTOR_KEEPS_DELETED_OBJECTS		|
								ESTOR_PROTECTED_KEY						|
								ESTOR_STATISTICS							|
								ESTOR_RECOVERY_BLOCKS;
			else {
				int ret =	ESTOR_CREATE_OBJECT						|
									ESTOR_DELETE_OBJECT						|
									ESTOR_MODIFY_ATTRIBUTES				|
									ESTOR_CREATE_STREAM						|
									ESTOR_DELETE_STREAM						|
									ESTOR_DISCARD_CHANGES					|
									ESTOR_KEEPS_DELETED_OBJECTS		|
									ESTOR_CAN_UNDELETE						|
									ESTOR_PROTECTED_KEY						|
									ESTOR_STATISTICS							|
									ESTOR_RECOVERY_BLOCKS;
				if (IsOpen() && !IsNewFileActive() && (bModified || statistics.nFixupSegments > 0 || statistics.uDataAreaUnused > 0)) ret |= ESTOR_CAN_BE_COMPRESSED;
				return ret;
			}
		}
		
		public StorageStatistics GetStorageStatistics() {
			StorageStatistics stat = new StorageStatistics();
			stat.uBaseSegmentSize = statistics.uBaseSegmentSize;
			stat.uAgentDataSize = statistics.uAgentDataSize;
			stat.uBaseDataAreaSize = statistics.uBaseDataAreaSize;
			stat.uDirectorySize = statistics.uDirectorySize;
			stat.nFixupSegments = statistics.nFixupSegments;
			stat.uTotalFixupSegmentSize = statistics.uTotalFixupSegmentSize;
			stat.uTotalFixupDataAreaSize = statistics.uTotalFixupDataAreaSize;
			stat.uTotalFixupListSize = statistics.uTotalFixupListSize;
			stat.nFixupRecords = statistics.nFixupRecords;
			stat.nObjects = statistics.nObjects;
			stat.nDeletedObjects = statistics.nDeletedObjects;
			stat.nAttributeBlocks = statistics.nAttributeBlocks;
			stat.uTotalAttributeSize = statistics.uTotalAttributeSize;
			stat.nStreams = statistics.nStreams;
			stat.uDataAreaUsed = statistics.uDataAreaUsed;
			stat.uDataAreaUnused = statistics.uDataAreaUnused;
			stat.uTotalStreamSize = statistics.uTotalStreamSize;
			stat.nRecoveryBlocks = statistics.nRecoveryBlocks;
			stat.uTotalRecoveryBlockSize = statistics.uTotalRecoveryBlockSize;
			return stat;
		}
		
		public byte[] GetAgentData() throws Exception {
			if (!IsOpen()) throw new Exception("Storage::GetAgentData : Container is not open.");
			return (agentData != null) ? Arrays.copyOf(agentData, agentData.length) : null;
		}
		
		public UUID GetCipherCID() throws Exception {
			if (!bHeaderAvailable) throw new Exception("Storage::GetCipherCID : Container is not open.");
			return cipherID;
		}
		
		public CipherParameters GetCipherParameters() throws Exception {
			if (!bHeaderAvailable) throw new Exception("Storage::GetCipherInfo : Container is not open.");
			return new CipherParameters(cipherParamBlock);
		}
		
		public String GetCipherName()  throws Exception{
			if (!bHeaderAvailable) throw new Exception("Storage::GetCipherName : Container is not open.");
			return cipherName;
		}
		
		public String GetCipherScheme() throws Exception {
			if (!bHeaderAvailable) throw new Exception("Storage::GetCipherScheme : Container is not open.");
			return cipherScheme;
		}
		
		public UUID GetCompressorCID() throws Exception {
			if (!bHeaderAvailable) throw new Exception("Storage::GetCompressorCID : Container is not open.");
			return compressorID;
		}
		
		public CompressorParameters GetCompressorParameters() throws Exception {
			if (!bHeaderAvailable) throw new Exception("Storage::GetCompressorParameters : Container is not open.");
			return new CompressorParameters(compressorParamBlock);
		}
		
		public String GetCompressorName() throws Exception {
			if (!bHeaderAvailable) throw new Exception("Storage::GetCompressorName : Container is not open.");
			return compressorName;
		}
		
		public String GetCompressorScheme() throws Exception {
			if (!bHeaderAvailable) throw new Exception("Storage::GetCompressorScheme : Container is not open.");
			return compressorScheme;
		}
		
		public UUID GetHashFunctionCID() throws Exception {
			if (!bHeaderAvailable) throw new Exception("Storage::GetHashFunctionCID : Container is not open.");
			return hashFunctionID;
		}
		
		public HashFunctionParameters GetHashFunctionParameters() throws Exception {
			if (!bHeaderAvailable) throw new Exception("Storage::GetHashFunctionParameters : Container is not open.");
			return new HashFunctionParameters(hashFunctionParamBlock);
		}
		
		public String GetHashFunctionName() throws Exception {
			if (!bHeaderAvailable) throw new Exception("Storage::GetHashFunctionName : Container is not open.");
			return hashFunctionName;
		}
		
		public String GetHashFunctionScheme() throws Exception {
			if (!bHeaderAvailable) throw new Exception("Storage::GetHashFunctionScheme : Container is not open.");
			return hashFunctionScheme;
		}
		
		public UUID GetKeyID() throws Exception {
			if (!bHeaderAvailable) throw new Exception("Storage::GetKeyID : Container is not open.");
			assert keyRecord != null;
			return keyRecord.keyMaterial;
		}
		
		public String GetKeyPath() throws Exception {
			if (!bHeaderAvailable) throw new Exception("Storage::GetKeyPath : Container is not open.");
			assert keyRecord != null;
			return keyRecord.keyPath;
		}
		
		public boolean TestPassword(String password) throws Exception {
			if (!bHeaderAvailable) throw new Exception("Storage::TestPassword : Container is not open.");
			if (!bTestPasswordContext) return false;	// Is not called from IKeyCallback
			assert keyRecord != null;
			if (keyRecord.keyMaterial != IDENT_PASSWORD && keyRecord.keyMaterial != IDENT_LOWERCASE_PASSWORD && keyRecord.keyMaterial != IDENT_PROTECTED_KEY) return false;
			
			KeyRecord kr = new KeyRecord();
			kr.keyMaterial = keyRecord.keyMaterial;
			kr.password = password;
			ConvertPassword(kr, GetHashFunctionCID());
			SetupHmac(kr, hashFunctionParamBlock.hashSize);
			return Arrays.equals(keyVerificator, ComputeVerificator(verificationPasses));
		}
	}
}
