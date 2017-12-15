/*******************************************************************************

  Product:       Kryptel/Java
  File:          Extractor.java
  Description:   https://www.kryptel.com/articles/developers/java/sk.php

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


package com.kryptel.silver_key;


import static com.kryptel.ApiHelpers.ConvertPassword;
import static com.kryptel.ApiHelpers.ExpectedKeyMaterial;
import static com.kryptel.Constants.BINARY_KEY_SIZE;
import static com.kryptel.Constants.DEFAULT_BUFFER_SIZE;
import static com.kryptel.Guids.CID_COMPRESSOR_ZIP;
import static com.kryptel.Guids.CID_HASH_SHA512;
import static com.kryptel.Guids.CID_HASH_SHA512_64;
import static com.kryptel.Guids.CID_HMAC;
import static com.kryptel.Guids.CID_SILVER_KEY;
import static com.kryptel.Guids.IID_IBlockCipherParams;
import static com.kryptel.Guids.IID_ICipher;
import static com.kryptel.Guids.IID_ICompressor;
import static com.kryptel.Guids.IID_IHashFunction;
import static com.kryptel.Guids.IID_IHashFunctionParams;
import static com.kryptel.Guids.IID_IMacSetup;
import static com.kryptel.Guids.IID_IMemoryBlockCompressor;
import static com.kryptel.Guids.IID_IRawBlockCipher;
import static com.kryptel.IProgressCallback.MIN_SIZE_TO_STEP;
import static com.kryptel.bslx.Conversions.GetAsInt;
import static com.kryptel.bslx.Conversions.GetAsLong;
import static com.kryptel.bslx.Conversions.GetAsShort;
import static com.kryptel.bslx.Conversions.UuidFromBytes;
import static com.kryptel.bslx.Targets.GetTargetName;
import static com.kryptel.bslx.Targets.TARGET_ASK_USER;
import static com.kryptel.silver_key.SilverKey.COMMAND_BACKGROUND;
import static com.kryptel.silver_key.SilverKey.COMMAND_BACKGROUND_PICTURE;
import static com.kryptel.silver_key.SilverKey.COMMAND_COMMENT;
import static com.kryptel.silver_key.SilverKey.COMMAND_DELETE;
import static com.kryptel.silver_key.SilverKey.COMMAND_DIRECTORY;
import static com.kryptel.silver_key.SilverKey.COMMAND_FILE;
import static com.kryptel.silver_key.SilverKey.COMMAND_LINK;
import static com.kryptel.silver_key.SilverKey.COMMAND_NULL;
import static com.kryptel.silver_key.SilverKey.COMMAND_OPEN;
import static com.kryptel.silver_key.SilverKey.COMMAND_PROGRESS;
import static com.kryptel.silver_key.SilverKey.COMMAND_SPLASH;
import static com.kryptel.silver_key.SilverKey.IsParcel;
import static com.kryptel.silver_key.SilverKey.SK_FLAG_SHOW_DESCRIPTION;
import static com.kryptel.silver_key.SilverKey.VerifyParcelMD5;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.UUID;

import com.kryptel.ApiHelpers;
import com.kryptel.IDataSink;
import com.kryptel.IKeyCallback;
import com.kryptel.IKryptelComponent;
import com.kryptel.INotification;
import com.kryptel.IProgressCallback;
import com.kryptel.IReplaceCallback;
import com.kryptel.KeyIdent;
import com.kryptel.KeyRecord;
import com.kryptel.Loader;
import com.kryptel.Message;
import com.kryptel.Progress;
import com.kryptel.IReplaceCallback.REPLACE_ACTION;
import com.kryptel.bslx.Conversions;
import com.kryptel.bslx.SmartBuffer;
import com.kryptel.cipher.IBlockCipherParams;
import com.kryptel.cipher.ICipher;
import com.kryptel.cipher.IRawBlockCipher;
import com.kryptel.compressor.ICompressor;
import com.kryptel.compressor.IMemoryBlockCompressor;
import com.kryptel.exceptions.UserAbortException;
import com.kryptel.hash_function.IHashFunction;
import com.kryptel.hash_function.IHashFunctionParams;
import com.kryptel.mac.IMacSetup;


final class Extractor implements ISilverKeyExtractor {
	Extractor(long capabilities) throws Exception {
		compCapabilities = capabilities;

		hmacComp = Loader.CreateComponent(CID_HMAC, compCapabilities);
		hmacSetup = (IMacSetup)hmacComp.GetInterface(IID_IMacSetup);
		
		compressorComp = Loader.CreateComponent(CID_COMPRESSOR_ZIP, compCapabilities);
		blockCompressor = (IMemoryBlockCompressor)compressorComp.GetInterface(IID_IMemoryBlockCompressor);
		streamCompressor = (ICompressor)compressorComp.GetInterface(IID_ICompressor);
	}
	
	void SetCapabilities(long capabilities) { }
	
	void Reset() throws IOException {
		if (parcelFile != null) {
			parcelFile.close();
			parcelFile = null;
		}
	}

	
  //
  // ISilverKeyExtractor
  //
	
	
	public void ExtractData(String targetDir, String parcelPath, Object arg, IKeyCallback keyFunc, IProgressCallback progressFunc, IReplaceCallback replaceCallback, IMessage msgCallback, INotification notificationCallback) throws Exception {
		if (targetDir == null || parcelPath == null || keyFunc == null) throw new Exception(Message.Get(Message.Code.InvalidArg));
		parcelFile = new RandomAccessFile(parcelPath, "r");
		
		try {
			if (!IsParcel(parcelFile, locator)) throw new Exception(Message.Get(Message.Code.InvalidParcel));
			if (!VerifyParcelMD5(parcelFile, locator, arg, progressFunc, Message.Code.ParcelIntegrity)) throw new Exception(Message.Get(Message.Code.CorruptedParcel));
			if (!locator.guidEngine.equals(CID_SILVER_KEY)) throw new Exception(Message.Get(Message.Code.WrongExtractor));
			if (locator.versionRequired > Engine.ENGINE_VERSION) throw new Exception(Message.Get(Message.Code.OldVersion));
			if (locator.versionCreated < Engine.MINIMAL_COMPATIBLE_ENGINE_VERSION) throw new Exception(Message.Get(Message.Code.IncompatibleVersion));
			
			LoadTrailer();
			LoadHeader();
			
			if ((flags & SK_FLAG_SHOW_DESCRIPTION) != 0 && msgCallback != null) {
				assert (!parcelDescription.isEmpty());
				if (!msgCallback.Show(parcelTitle, parcelDescription)) throw new UserAbortException();
			}

			hmacSetup.SetBase((locator.versionRequired >= Engine.ENGINE_VERSION_WITH_CORRECT_HMAC) ? CID_HASH_SHA512 : CID_HASH_SHA512_64);
			hmacParams = (IHashFunctionParams)hmacComp.GetInterface(IID_IHashFunctionParams);
			hmacFunc = (IHashFunction)hmacComp.GetInterface(IID_IHashFunction);

			cipherComp = com.kryptel.cipher.ComponentLoader.CreateComponent(guidCipher, compCapabilities);
			if (cipherComp == null) throw new Exception(Message.Get(Message.Code.CompNotFound));
			cipherParams = (IBlockCipherParams)cipherComp.GetInterface(IID_IBlockCipherParams);
			rawBlockCipher = (IRawBlockCipher)cipherComp.GetInterface(IID_IRawBlockCipher);
			streamCipher = (ICipher)cipherComp.GetInterface(IID_ICipher);
			
			cipherParams.SetKeySize(cipherKeySize);
			cipherParams.SetBlockSize(cipherBlockSize);
			cipherParams.SetRounds(cipherRounds);
			cipherParams.SetScheme(cipherScheme);
			cipherParams.SetChainingMode(cipherChainingMode);
			
			keyRecord = keyFunc.Callback(arg, parcelTitle, ExpectedKeyMaterial(guidKey), guidKey);
			if (keyRecord == null) throw new Exception(Message.Get(Message.Code.UserAbort));
			if (keyRecord.keyMaterial.equals(KeyIdent.IDENT_PASSWORD) || keyRecord.keyMaterial.equals(KeyIdent.IDENT_LOWERCASE_PASSWORD)) ConvertPassword(keyRecord, CID_HASH_SHA512);
			
			cipherParams.SetKey(keyRecord.keyData, 0, cipherParams.GetKeySize());
			SetupHmacKey(keyRecord);

			try {
				if (notificationCallback != null) notificationCallback.ShowNotification(Message.Code.VerifyingPassword);
				byte[] keyVerificator = ComputeVerificator(verificationPasses);
				if (!Arrays.equals(verificator, keyVerificator)) throw new Exception(Message.Get(Message.Code.WrongKey));
			}
			finally {
				if (notificationCallback != null) notificationCallback.DismissNotification();
			}
			
			byte[] computedHmac = ApiHelpers.ComputeAreaHash(parcelFile, locator.parcelStart, fileAreaStart,
					hmacFunc, arg, progressFunc, Message.Code.DetectTampering);
			if (!Arrays.equals(computedHmac, headerHmac)) throw new Exception(Message.Get(Message.Code.TamperedPacel));
			computedHmac = ApiHelpers.ComputeAreaHash(parcelFile, locator.parcelStart + fileAreaStart, scriptAreaStart - fileAreaStart,
					hmacFunc, arg, progressFunc, Message.Code.DetectTampering);
			if (!Arrays.equals(computedHmac, fileAreaHmac)) throw new Exception(Message.Get(Message.Code.TamperedPacel));
			computedHmac = ApiHelpers.ComputeAreaHash(parcelFile, locator.parcelStart + scriptAreaStart, trailerStart - scriptAreaStart,
					hmacFunc, arg, progressFunc, Message.Code.DetectTampering);
			if (!Arrays.equals(computedHmac, scriptAreaHmac)) throw new Exception(Message.Get(Message.Code.TamperedPacel));

			rawBlockCipher.EncryptBlock(initVector, 0, initVector, 0);
			
			ReadScriptArea();

			nDirsCreated = nFilesCreated = 0;
			bytesWritten = 0;
			nDirs = nFiles = -1;		// mark as unknown
			totalBytes = -1;				// mark as unknown
			
			Progress progress = null;
			
			// Main extraction loop
			
			main_loop: for (;;) {
				switch (FetchInt()) {
					case COMMAND_NULL:
						if (progress != null) progress.Discard();
						break main_loop;
						
					case COMMAND_PROGRESS:
						nDirs = FetchInt();
						nFiles = FetchInt();
						totalBytes = FetchLong();
						if (progressFunc != null && totalBytes >= MIN_SIZE_TO_STEP)
							progress = new Progress(progressFunc, arg, (nFiles > 1) ? totalBytes : 0);
						break;
						
					case COMMAND_COMMENT:
						if (msgCallback != null ){
							scriptBuffer.Retrieve(ioBuf, 0, cipherParams.GetBlockSize());
							cipherParams.SetInitVector(ioBuf, 0, cipherParams.GetBlockSize());
							long commentPos = FetchLong() + locator.parcelStart;
							scriptBuffer.SkipBytes(4);
							int commentSize = FetchInt();

							streamCipher.Init(new SmallDataDecryptionSink(), commentBuffer);
							
							parcelFile.seek(commentPos);
							int len;
							
							while (commentSize > 0) {
								len = (int)Math.min(commentSize, ioBuf.length);
								parcelFile.read(ioBuf, 0, len);
								streamCipher.Decrypt(ioBuf, 0, len);
								commentSize -= len;
							}
							streamCipher.Done();
							
							String msg = new String(commentBuffer.Merge(), 0, commentBuffer.Size(), "UnicodeLittleUnmarked");
							if (!msgCallback.Show(parcelTitle, msg)) throw new UserAbortException();

							commentBuffer.Empty();
						}
						else
							scriptBuffer.SkipBytes(cipherParams.GetBlockSize() + 8 + 4 + 4);
						break;
						
					case COMMAND_BACKGROUND:
						scriptBuffer.SkipBytes(12);
						break;
						
					case COMMAND_BACKGROUND_PICTURE:
						scriptBuffer.SkipBytes(cipherParams.GetBlockSize() + 20);
						break;
						
					case COMMAND_SPLASH:
						scriptBuffer.SkipBytes(cipherParams.GetBlockSize() + 28);
						break;
						
					case COMMAND_DIRECTORY:
						{
							int target = FetchInt();
							String subdir = FetchString();
							String path = GetFullPath(targetDir, target, subdir);
							File dir = new File(path);
							dir.mkdirs();
							nDirsCreated++;
						}
						break;
						
					case COMMAND_LINK:
						scriptBuffer.SkipBytes(12);
						for (int i = 0; i < 5; i++) FetchString();
						break;
						
					case COMMAND_FILE:
						{
							scriptBuffer.Retrieve(ioBuf, 0, cipherParams.GetBlockSize());
							cipherParams.SetInitVector(ioBuf, 0, cipherParams.GetBlockSize());

							long streamPos = FetchLong() + locator.parcelStart;
							long fileSize = FetchLong();
							long streamSize = FetchLong();
							long fileTime = FetchLong();
							int target = FetchInt();
							String path = GetFullPath(targetDir, target, FetchString());
							File fn = new File(path);
							
							// Create parent dirs if necessary
							String dir = fn.getParent();
							if (dir != null) {
								File fDir = new File(dir);
								fDir.mkdirs();
							}

							if (progress != null && !progress.NewFile(fn.getName(), fileSize)) throw new UserAbortException();
							
							if (replaceCallback != null) {
								StringBuilder sb;
								rename_loop: while (fn.exists()) {
									sb = new StringBuilder(fn.getName());
									REPLACE_ACTION ra = replaceCallback.Callback(arg, sb, fileSize, fileTime, path, fn.length(), fn.lastModified() / 1000);
									switch (ra) {
										case REPLACE:
											break rename_loop;
											
										case RENAME:
											path = GetFullPath(targetDir, target, sb.toString());
											fn = new File(path);
											break;
										
										case ABORT:
											throw new UserAbortException();

										case SKIP:
										default:
											if (progress != null) progress.Step(fileSize);
											continue main_loop;
									}
								}
							}
							else {
								if (progress != null) progress.Step(fileSize);
								break;
							}
							
							streamCipher.Init(new FileDecryptionSink(), new FileOutputStream(path));
							
							parcelFile.seek(streamPos);
							int len;
							
							while (streamSize > 0) {
								len = (int)Math.min(streamSize, ioBuf.length);
								parcelFile.read(ioBuf, 0, len);
								streamCipher.Decrypt(ioBuf, 0, len);
								streamSize -= len;
								
								if (progress != null && !progress.Step(len)) throw new UserAbortException();
							}
							streamCipher.Done();
							
							nFilesCreated++;

							// Not supported on Android
					    //BasicFileAttributeView attributes = Files.getFileAttributeView(Paths.get(path), BasicFileAttributeView.class);
					    //FileTime time = FileTime.from(fileTime, TimeUnit.SECONDS);
					    //attributes.setTimes(time, time, time);
						}
						break;
						
					case COMMAND_DELETE:
						scriptBuffer.SkipBytes(4);
						FetchString();
						break;
						
					case COMMAND_OPEN:
						scriptBuffer.SkipBytes(8);
						FetchString();
						break;
						
					default:
						throw new Exception(Message.Get(Message.Code.UnknownScriptCommand));
				}
			}
			
			if (progress != null) progress.Discard();
		}
		finally {
			parcelFile.close();
			parcelFile = null;
		}
	}
	
	
	public ParcelStatistics GetExtractionStatistics() {
		ParcelStatistics ps = new ParcelStatistics();
		ps.nDirs = nDirs;
		ps.nFiles = nFiles;
		ps.totalBytes = totalBytes;
		ps.nDirsCreated = nDirsCreated;
		ps.nFilesCreated = nFilesCreated;
		ps.bytesWritten = bytesWritten;
		return ps;
	}

	
  //
  // Private data and methods
  //
	
	private static final int HASH_SIZE = 64;		// This engine uses SHA-512
	
	private long compCapabilities;
	
	private RandomAccessFile parcelFile;
	private ParcelLocator locator = new ParcelLocator();

	private KeyRecord keyRecord;
	
	private byte[] ioBuf = new byte [DEFAULT_BUFFER_SIZE];
	private SmartBuffer scriptBuffer = new SmartBuffer();
	private SmartBuffer commentBuffer = new SmartBuffer();

	// Parcel trailer
	
	byte[] headerHmac = new byte [HASH_SIZE];
	byte[] fileAreaHmac = new byte [HASH_SIZE];
	byte[] scriptAreaHmac = new byte [HASH_SIZE];
	UUID guidParcelTrailer;
	long fileAreaStart;
	long scriptAreaStart;
	long trailerStart;
	
	// Parcel header
	
	short versionCreated;
	short versionRequired;
	int flags;
	UUID guidEngine;
	UUID guidParcel;
	UUID guidCipher;
	int cipherKeySize;
	int cipherBlockSize;
	int cipherRounds;
	byte cipherScheme;
	int cipherChainingMode;
	UUID guidKey;
	short keyAssocDataSize;
	byte[] keyAssocData;
	int verificationPasses;			// Zero if no verificator
	byte[] verificator = new byte [HASH_SIZE];
	// End of pre-loaded part
	byte[] initVector;
	String cipherName;
	String cipherSchemeName;
	String parcelTitle;
	String parcelDescription;
	
	// Decryption statistics
	int nDirs = 0, nFiles = 0;
	long totalBytes = 0;
	int nDirsCreated = 0, nFilesCreated = 0;
	long bytesWritten = 0;
	
	// Components used
	private IKryptelComponent hmacComp;
	private IMacSetup hmacSetup;
	private IHashFunctionParams hmacParams;
	private IHashFunction hmacFunc;
	
	private IKryptelComponent compressorComp;
	private IMemoryBlockCompressor blockCompressor;
	private ICompressor streamCompressor;

	private IKryptelComponent cipherComp;
	private IBlockCipherParams cipherParams;
	private IRawBlockCipher rawBlockCipher;
	private ICipher streamCipher;

	
	class SmallDataDecompressionSink implements IDataSink {
		private SmartBuffer smBuf;
		public void Init(Object arg) throws Exception { smBuf = (SmartBuffer)arg; smBuf.Empty(); }
		public void PutData(byte[] buf, int start, int size) throws Exception { smBuf.Store(buf, start, size); }
		public void Done() throws Exception { }
	}
	class SmallDataDecryptionSink implements IDataSink {
		public void Init(Object arg) throws Exception { streamCompressor.Init(new SmallDataDecompressionSink(), arg); }
		public void PutData(byte[] buf, int start, int size) throws Exception { streamCompressor.Decompress(buf, start, size); }
		public void Done() throws Exception { streamCompressor.Done(); }
	}
	

	
	class FileDecompressionSink implements IDataSink {
		private FileOutputStream fos;
		public void Init(Object arg) throws Exception { fos = (FileOutputStream)arg; }
		public void PutData(byte[] buf, int start, int size) throws Exception { fos.write(buf, start, size); bytesWritten += size; }
		public void Done() throws Exception { fos.close(); }
	}
	class FileDecryptionSink implements IDataSink {
		public void Init(Object arg) throws Exception { streamCompressor.Init(new FileDecompressionSink(), arg); }
		public void PutData(byte[] buf, int start, int size) throws Exception { streamCompressor.Decompress(buf, start, size); }
		public void Done() throws Exception { streamCompressor.Done(); }
	}
	
	private void SetupHmacKey(KeyRecord keyRecord) throws Exception {
		assert (keyRecord.keyData.length > 0 && keyRecord.keyData.length <= BINARY_KEY_SIZE);
		byte[] hmacKey = new byte [BINARY_KEY_SIZE];
		Arrays.fill(hmacKey, (byte)0);
		for (int i = 0, j = keyRecord.keyData.length; i < keyRecord.keyData.length; ) hmacKey[i++] = (byte)(~keyRecord.keyData[--j]);
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
	
	
	private void LoadTrailer() throws Exception {
		byte[] buf = new byte [16];
		trailerStart = locator.parcelSize - (3 * HASH_SIZE + 4 + 16 + 3 * 8);
		parcelFile.seek(locator.parcelStart + trailerStart);
		parcelFile.read(headerHmac, 0, HASH_SIZE);
		parcelFile.read(fileAreaHmac, 0, HASH_SIZE);
		parcelFile.read(scriptAreaHmac, 0, HASH_SIZE);
		parcelFile.seek(locator.parcelStart + trailerStart + 3 * HASH_SIZE + 4);		// Skip parcel end tag, we know it is ok
		parcelFile.read(buf, 0, 16);
		guidParcelTrailer = UuidFromBytes(buf, 0);
		parcelFile.read(buf, 0, 8);
		fileAreaStart = GetAsLong(buf, 0);
		parcelFile.read(buf, 0, 8);
		scriptAreaStart = GetAsLong(buf, 0);
	}
	
	
	private void LoadHeader() throws Exception {
		byte[] buf = new byte [128];

		parcelFile.seek(locator.parcelStart + 4);
		parcelFile.read(buf, 0, 92);

		versionCreated = GetAsShort(buf, 0);
		versionRequired = GetAsShort(buf, 2);
		
		guidEngine = UuidFromBytes(buf, 4);
		guidParcel = UuidFromBytes(buf, 20);
		flags = GetAsInt(buf, 36);
		
		guidCipher = UuidFromBytes(buf, 40);
		cipherKeySize = GetAsInt(buf, 56);
		cipherBlockSize = GetAsInt(buf, 60);
		cipherRounds = GetAsInt(buf, 64);
		cipherScheme = (byte)GetAsInt(buf, 68);
		cipherChainingMode = GetAsInt(buf, 72);
		
		guidKey = UuidFromBytes(buf, 76);
		if (guidKey.equals(KeyIdent.IDENT_YUBIKEY) || guidKey.equals(KeyIdent.IDENT_YUBIKEY_PASSWORD)) {
			throw new Exception(Message.Get(Message.Code.UnsupportedKeyMaterial));
			/*
			parcelFile.read(buf, 0, 2);
			keyAssocDataSize = GetAsShort(buf, 0);
			if (keyAssocDataSize > 0) {
				keyAssocData = new byte [keyAssocDataSize];
				parcelFile.read(keyAssocData, 0, keyAssocDataSize);
			}
			*/
		}
		
		parcelFile.read(buf, 0, 4);
		verificationPasses = GetAsInt(buf, 0);
		verificator = new byte [HASH_SIZE];
		parcelFile.read(verificator, 0, HASH_SIZE);
		
		initVector = new byte [cipherBlockSize];
		parcelFile.read(initVector, 0, cipherBlockSize);

		cipherName = ReadString();
		cipherSchemeName = ReadString();
		parcelTitle = ReadString();

		if ((flags & SK_FLAG_SHOW_DESCRIPTION) != 0) {
			parcelFile.read(buf, 0, 8);
			int comprLength = GetAsInt(buf, 4);
			byte[] descr = new byte [comprLength];
			parcelFile.read(descr);
			
			parcelDescription = blockCompressor.DecompressWideString(descr, 0, descr.length);
		}
		else
			parcelDescription = null;
	}

	
	private String ReadString() throws IOException {
		byte[] buf = new byte [2];
		parcelFile.read(buf, 0, 2);
		short len = GetAsShort(buf, 0);
		
		buf = new byte [len * 2];
		parcelFile.read(buf);
		return new String(buf, 0, buf.length, "UnicodeLittleUnmarked");
	}
	
	
	private void ReadScriptArea() throws Exception {
		cipherParams.SetInitVector(initVector, 0, initVector.length);
		streamCipher.Init(new SmallDataDecryptionSink(), scriptBuffer);
		
		parcelFile.seek(locator.parcelStart + scriptAreaStart);
		long scriptSize = trailerStart - scriptAreaStart;
		int len;
		
		while (scriptSize > 0) {
			len = (int)Math.min(scriptSize, ioBuf.length);
			parcelFile.read(ioBuf, 0, len);
			streamCipher.Decrypt(ioBuf, 0, len);
			scriptSize -= len;
		}
		streamCipher.Done();
	}

	
	private int FetchInt() {
		scriptBuffer.Retrieve(ioBuf, 0, 4);
		return GetAsInt(ioBuf, 0);
	}

	
	private long FetchLong() {
		scriptBuffer.Retrieve(ioBuf, 0, 8);
		return GetAsLong(ioBuf, 0);
	}

	
	private String FetchString() throws UnsupportedEncodingException {
		scriptBuffer.Retrieve(ioBuf, 0, 2);
		short len = (short)(GetAsShort(ioBuf, 0) * 2);
		scriptBuffer.Retrieve(ioBuf, 0, len);
		return new String(ioBuf, 0, len, "UnicodeLittleUnmarked");
	}
	
	
	private String GetFullPath(String basePath, int target, String dir) {
		StringBuilder sbRet = new StringBuilder(basePath);
		if (sbRet.length() == 0 || (sbRet.charAt(sbRet.length() - 1) != '/' && sbRet.charAt(sbRet.length() - 1) != '\\')) sbRet.append('/');
		
		if (target != TARGET_ASK_USER) {
			sbRet.append(GetTargetName(target));
			sbRet.append('/');
		}

		sbRet.append(dir);
		
		for (int i = 0; i < sbRet.length(); i++) {
			if ((sbRet.charAt(i) == '/' || sbRet.charAt(i) == '\\') && sbRet.charAt(i) != File.separatorChar) {
				sbRet.deleteCharAt(i);
				sbRet.insert(i, File.separatorChar);
			}
		}
		
		if (sbRet.length() > 0 && sbRet.charAt(sbRet.length() - 1) == File.separatorChar) sbRet.deleteCharAt(sbRet.length() - 1);
		return sbRet.toString();
	}
}
