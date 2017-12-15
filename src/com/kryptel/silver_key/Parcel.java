/*******************************************************************************

  Product:       Kryptel/Java
  File:          Parcel.java
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
import static com.kryptel.Capabilities.*;
import static com.kryptel.Constants.*;
import static com.kryptel.Guids.*;
import static com.kryptel.bslx.Targets.*;
import static com.kryptel.silver_key.SilverKey.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import com.kryptel.*;
import com.kryptel.bslx.*;
import com.kryptel.cipher.*;
import com.kryptel.compressor.*;
import com.kryptel.exceptions.UserAbortException;
import com.kryptel.hash_function.*;
import com.kryptel.mac.IMacSetup;


final class Parcel implements ISilverKeyParcel {
	Parcel(long capabilities) throws Exception {
		compCapabilities = capabilities;
		
		parcelMD5 = MessageDigest.getInstance("MD5");

		rand = new SecureRandom();
		rand.setSeed(rand.generateSeed(256 / 8));

		hmacComp = Loader.CreateComponent(CID_HMAC, compCapabilities);
		hmacSetup = (IMacSetup)hmacComp.GetInterface(IID_IMacSetup);
		hmacSetup.SetBase(CID_HASH_SHA512);
		hmacParams = (IHashFunctionParams)hmacComp.GetInterface(IID_IHashFunctionParams);
		hmacFunc = (IHashFunction)hmacComp.GetInterface(IID_IHashFunction);
		
		compressorComp = Loader.CreateComponent(CID_COMPRESSOR_ZIP, compCapabilities);
		compressorParams = (ICompressorParams)compressorComp.GetInterface(IID_ICompressorParams);
		blockCompressor = (IMemoryBlockCompressor)compressorComp.GetInterface(IID_IMemoryBlockCompressor);
		streamCompressor = (ICompressor)compressorComp.GetInterface(IID_ICompressor);
		compressorParams.SetLevel(CT_MAX_COMPRESSION);
	}
	
	void SetCapabilities(long capabilities) { compCapabilities = capabilities; }
	
  //
  // ISilverKeyParcel
  //

	public void SetParcelTitle(String title) throws Exception {
		if (dataSink != null) throw new Exception(Message.Get(Message.Code.InvalidState));
		if (title != null && !title.isEmpty()) parcelTitle = title;
	}
	
	public void AttachDescription(String description) throws Exception {
		if (dataSink != null) throw new Exception(Message.Get(Message.Code.InvalidState));
		parcelDescription = description;
	}

	public ISilverKeyStream Create(String fileName, PARCEL_TYPE type, IKryptelComponent cipher, Object arg, IKeyCallback keyFunc, IProgressCallback progressFunc) throws Exception {
		class Sink implements IDataSink {
			private FileOutputStream fout;
			private String fileName;
			public Sink(String fileName) { this.fileName = fileName; }
			public void Init(Object arg) throws Exception { fout = new FileOutputStream(fileName); }
			public void PutData(byte[] buf, int start, int size) throws Exception { fout.write(buf, start, size); }
			public void Done() throws Exception { fout.close(); }
		}
		return Create(new Sink(fileName), null, fileName, type, cipher, arg, keyFunc, progressFunc);
	}

	public ISilverKeyStream Create(IDataSink sink, Object sinkArg, String fileName, PARCEL_TYPE type, IKryptelComponent cipher, Object arg, IKeyCallback keyFunc, IProgressCallback progressFunc) throws Exception {
		if (dataSink != null) throw new Exception(Message.Get(Message.Code.InvalidState));
		if (sink == null || cipher == null || keyFunc == null) throw new Exception(Message.Get(Message.Code.InvalidArg));
		dataSink = sink;
		dataSinkArg = sinkArg;
		dataSinkInitialized = false;
		
		callbackArg = arg;
		progressCallback = progressFunc;
		
		parcelType = type;
		parcelFileName = fileName;

		cipherComp = cipher;
		cipherParams = (IBlockCipherParams)cipherComp.GetInterface(IID_IBlockCipherParams);
		rawBlockCipher = (IRawBlockCipher)cipherComp.GetInterface(IID_IRawBlockCipher);
		streamCipher = (ICipher)cipherComp.GetInterface(IID_ICipher);
		
		keyRecord = keyFunc.Callback(arg, parcelTitle, IKeyCallback.PASSWORDS | IKeyCallback.BINARY_KEY, null);
		if (keyRecord == null) throw new UserAbortException();
		if (keyRecord.keyMaterial.equals(KeyIdent.IDENT_PASSWORD) || keyRecord.keyMaterial.equals(KeyIdent.IDENT_LOWERCASE_PASSWORD)) ConvertPassword(keyRecord, CID_HASH_SHA512);
		
		cipherParams.SetKey(keyRecord.keyData, 0, cipherParams.GetKeySize());
		SetupHmacKey(keyRecord);
		
		initVector = new byte [cipherParams.GetBlockSize()];
		rand.nextBytes(initVector);
		
		parcelGuid = CID_PARCEL_GUID;
		
		parcelFlags = 0;
		if (parcelDescription != null && !parcelDescription.isEmpty()) parcelFlags |= SK_FLAG_SHOW_DESCRIPTION;

		nDirectories = 0;
		nFiles = 0;
		uTotalBytes = 0;
		
		script = new ArrayList<Element>();
		
		return new ParcelStream();
	}

	public void Close() throws Exception {
		if (dataSink == null) return;
		
		FileInputStream base = null;
		
		try {
			parcelStart = 0;
			currentPos = 0;
			
			if (parcelType != PARCEL_TYPE.STUBLESS) {
			
				if (parcelType == PARCEL_TYPE.APPEND) {
					if ((compCapabilities & CAP_HIDDEN_PARCELS) == 0) throw new Exception(Message.Get(Message.Code.UnsupportedCap));
					
					File baseFile = new File(parcelFileName);
					String bakName = parcelFileName + ".BAK";
	
					if (!baseFile.renameTo(new File(bakName))) {
						for (int i = 1; i <= (MAX_BASE_FILE_COPIES + 1); i++) {
							if (i == (MAX_BASE_FILE_COPIES + 1)) throw new Exception(Message.Get(Message.Code.BaseFileRenameError));
							bakName = parcelFileName + ".BAK(" + i + ")";
							if (baseFile.renameTo(new File(bakName))) break;
						}
					}
					
					base = new FileInputStream(bakName);
				}
				else {
					assert (parcelType == PARCEL_TYPE.STUB);
					String stubFileName = SilverKey.GetStubDirectory() + cipherComp.ComponentName() + ".stub";
					base = new FileInputStream(stubFileName);
				}
				
				// Copy base file or stub to data sink
				
				long flen = base.getChannel().size();
				
				dataSink.Init(dataSinkArg);
				dataSinkInitialized = true;
				
				byte[] buffer = new byte [DEFAULT_BUFFER_SIZE];
				int len;

				while (flen > 0) {
					len = (int)Math.min(flen, buffer.length);
					base.read(buffer, 0, len);
					dataSink.PutData(buffer, 0, len);
					parcelStart += len;
				}
				
				base.close();
				base = null;
			}
			else {		// PARCEL_TYPE.STUBLESS
				dataSink.Init(dataSinkArg);
				dataSinkInitialized = true;
			}

			WriteHeader();
			fileAreaOffset = currentPos;
			WriteParcelData();
			scriptAreaOffset = currentPos;
			WriteParcelScript();
			
			// Creating trailer
			Store(WriteNoHmac, headerHmac);
			Store(WriteNoHmac, fileAreaHmac);
			Store(WriteNoHmac, scriptAreaHmac);
			
			int tag = PARCEL_END_TAG;
			Store(WriteNoHmac, tag);
			Store(WriteNoHmac, Conversions.UuidToBytes(parcelGuid));
			
			Store(WriteNoHmac, fileAreaOffset);
			Store(WriteNoHmac, scriptAreaOffset);
			Store(WriteNoHmac, parcelStart);
			
			byte[] hashMD5 = parcelMD5.digest();
			Store(PureWrite, hashMD5);

			if (parcelType == PARCEL_TYPE.APPEND) {
				int junkSize = (int)(rand.nextDouble() * (TRAILING_JUNK_MAX_SIZE - TRAILING_JUNK_MIN_SIZE) + TRAILING_JUNK_MIN_SIZE);
				byte[] junkData = new byte [junkSize];
				rand.nextBytes(junkData);
				Store(PureWrite, junkData);
			}
		}
		finally {
			if (base != null) base.close();
			CleanUp();
		}
	}

	
  //
  // ISilverKeyStream implementation
  //

	private class ParcelStream implements ISilverKeyStream {
		public void CreateDirectory(String targetedPath) throws Exception {
			if (dataSink == null) throw new Exception(Message.Get(Message.Code.InvalidState));
			script.add(new DirectoryElement(targetedPath));
		}

		public void StoreFile(String targetedPath, String srcPath) throws Exception {
			if (dataSink == null) throw new Exception(Message.Get(Message.Code.InvalidState));
			script.add(new FileElement(targetedPath, srcPath));
		}
		
		public void StoreTree(String targetedPath, String srcPath) throws Exception {
			if (dataSink == null) throw new Exception(Message.Get(Message.Code.InvalidState));

			File item = new File(srcPath);
			if (item.isFile()) {
				script.add(new FileElement(targetedPath, srcPath));
				return;
			}
			
			// It is a directory
			
			script.add(new DirectoryElement(targetedPath));
			
			String[] itemList = item.list();
			for (String fileName: itemList) {
				StoreTree(targetedPath + SK_PATH_SEPARATOR + fileName, srcPath + File.separator + fileName);
			}
		}

		public void AddMessage(String message) throws Exception {
			if (dataSink == null) throw new Exception(Message.Get(Message.Code.InvalidState));
			script.add(new CommentElement(message));
		}
	}

	
  //
  // This class family represent script elements
  //

	private abstract class Element {
		public void StoreElement() throws Exception { }
		public abstract void StoreCommand() throws Exception;
		
		protected byte[] elemInitVector;
		protected long dataOffset;
		protected long originalSize = -1;		// Invalid value shows that StoreElement has not been called (or the element is not a file)
		protected long storedSize;
		protected long fileTime = 0;
	
		protected void StoreFile(String fileName) throws Exception {
			File f = new File(fileName);
			assert (f.isFile());
			fileTime = f.lastModified() / 1000;
			originalSize = f.length();
			if (originalSize == 0) {
				dataOffset = storedSize = 0;
				return;
			}
			
			try (FileInputStream fin = new FileInputStream(fileName)) {
				dataOffset = currentPos;
				
				elemInitVector = new byte [cipherParams.GetBlockSize()];
				rand.nextBytes(elemInitVector);
				cipherParams.SetInitVector(elemInitVector, 0, elemInitVector.length);
				
				compressorParams.SetLevel(GetCompressionLevel(fileName));
				CompressSink sink = new CompressSink();
				streamCompressor.Init(sink, null);
				
				if (progress != null && !progress.NewFile(f.getName(), originalSize)) throw new UserAbortException();
				
				long fsize = originalSize;
				int len;
				while (fsize > 0) {
					len = (int)Math.min(fsize, ioBuffer.length);
					fin.read(ioBuffer, 0, len);
					streamCompressor.Compress(ioBuffer, 0, len);
					fsize -= len;
					
					if (progress != null && !progress.Step(len)) throw new UserAbortException();
				}
				
				streamCompressor.Done();
				storedSize = currentPos - dataOffset;
			}
		}

		private byte GetCompressionLevel(String fileName) {
			for (String s: nonCompressible) {
				int len = s.length();
				int pos = fileName.length() - len;
				if ((pos > 0) && fileName.substring(pos).equalsIgnoreCase(s)) return CT_NO_COMPRESSION;
			}
			return CT_MAX_COMPRESSION;
		}
	}
	
	
	private class CommentElement extends Element {
		CommentElement(String message) {
			comment = message;
		}

		public void StoreElement() throws Exception {
			dataOffset = currentPos;
			
			elemInitVector = new byte [cipherParams.GetBlockSize()];
			rand.nextBytes(elemInitVector);
			cipherParams.SetInitVector(elemInitVector, 0, elemInitVector.length);
			
			compressorParams.SetLevel(CT_MAX_COMPRESSION);
			CompressSink sink = new CompressSink();
			streamCompressor.Init(sink, null);
			
			byte[] byteSeq = comment.getBytes("UnicodeLittleUnmarked");
			
			streamCompressor.Compress(byteSeq, 0, byteSeq.length);
			streamCompressor.Done();

			commentSize = byteSeq.length / 2;
			compressedSize = (int)(currentPos - dataOffset);
		}
		
		public void StoreCommand() throws Exception {
			int tag = COMMAND_COMMENT;
			Store(EncryptAndWrite, tag);
			Store(EncryptAndWrite, elemInitVector);
			Store(EncryptAndWrite, dataOffset);
			Store(EncryptAndWrite, commentSize);
			Store(EncryptAndWrite, compressedSize);
		}

		protected String comment;
		protected int commentSize;
		protected int compressedSize;
	}
	
	
	private abstract class TargetedElement extends Element {
		protected int target;
		protected String path;
		
		public TargetedElement(String targetedPath) throws Exception {
			assert (targetedPath != null && !targetedPath.isEmpty());
			String[] pathParts = targetedPath.split("\\" + TARGET_SEPARATOR);
			assert (pathParts.length == 2 && !pathParts[0].isEmpty() && !pathParts[1].isEmpty());
			target = GetTargetCode(pathParts[0]);
			if (target == TARGET_UNKNOWN) throw new Exception(Message.Get(Message.Code.UnknownTarget));
			if (target == TARGET_ASK_USER) parcelFlags |= SK_FLAG_ASK_DIR;

			StringBuilder skpath = new StringBuilder(pathParts[1].length());
			String[] pathElems = pathParts[1].split("[/\\\\]");
			for (String e: pathElems) {
				if (skpath.length() != 0) skpath.append(SK_PATH_SEPARATOR);
				skpath.append(e);
			}
			path = skpath.toString();
		}
	}
	
	
	private class DirectoryElement extends TargetedElement {
		
		public DirectoryElement(String targetedPath) throws Exception {
			super(targetedPath);
			nDirectories++;
		}
		
		public void StoreCommand() throws Exception {
			int tag = COMMAND_DIRECTORY;
			Store(EncryptAndWrite, tag);
			Store(EncryptAndWrite, target);
			Store(EncryptAndWrite, path);
		}
	}
	
	
	private class FileElement extends TargetedElement {
		private String srcPath;
		
		public FileElement(String targetedPath, String sourcePath) throws Exception {
			super(targetedPath);
			assert (sourcePath != null && !sourcePath.isEmpty());
			srcPath = sourcePath;
			nFiles++;
			
			File f = new File(srcPath);
			uTotalBytes += f.length();
		}

		public void StoreElement() throws Exception {
			StoreFile(srcPath);
		}
		
		public void StoreCommand() throws Exception {
			assert (originalSize >= 0);		// This condition shows that StoreElement(StoreFile) has been called
			int tag = COMMAND_FILE;
			Store(EncryptAndWrite, tag);
			Store(EncryptAndWrite, elemInitVector);
			Store(EncryptAndWrite, dataOffset);
			Store(EncryptAndWrite, originalSize);
			Store(EncryptAndWrite, storedSize);
			Store(EncryptAndWrite, fileTime);
			Store(EncryptAndWrite, target);
			Store(EncryptAndWrite, path);
		}
	}

	
  //
  // Various helper methods
  //
	
	boolean IsOpen() { return dataSink != null; }
	
	void Reset() throws Exception { CleanUp(); }

	
  //
  // Private data and methods
  //
	
	private static final short ENGINE_VERSION_CREATED				= Engine.ENGINE_VERSION;
	private static final short EXTRACTOR_VERSION_REQUIRED		= (short)0x0700;
	
	private static final int FILE_AREA_OBFUSCATION_THRESHOLD		= (32 * 1024);
	private static final int SCRIPT_AREA_OBFUSCATION_THRESHOLD	= 512;

	private static final int TRAILING_JUNK_MIN_SIZE				= 215;					// Trailing random data for
	private static final int TRAILING_JUNK_MAX_SIZE				= 4128;					//   attachment (hidden) parcel obfuscation
	
	private static final String defaultParcelTitle = "Silver Key parcel";
	
	private static String[] nonCompressible = { ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".flac", ".ape", ".mp4", ".mov", ".zip", ".rar", ".7z" };
	
	private long compCapabilities;
	
	private String parcelTitle = defaultParcelTitle;
	private String parcelDescription;
	
	private IDataSink dataSink;
	private Object dataSinkArg;
	private boolean dataSinkInitialized;

	private Object callbackArg;

	private PARCEL_TYPE parcelType;
	private String parcelFileName;

	private KeyRecord keyRecord;
	private byte[] initVector;
	
	UUID parcelGuid;
	private int parcelFlags;
	
	byte[] ioBuffer = new byte [DEFAULT_BUFFER_SIZE];
	
	long parcelStart;
	long fileAreaOffset;
	long scriptAreaOffset;
	long currentPos;		// Parcel position; the file position is parcelStart + currentPos

	MessageDigest parcelMD5;
	
	byte[] headerHmac;
	byte[] fileAreaHmac;
	byte[] scriptAreaHmac;

	private int nDirectories;
	private int nFiles;
	private long uTotalBytes;
	
	List<Element> script;
	
	IProgressCallback progressCallback;
	Progress progress;
	
	// Components used
	
	private SecureRandom rand;
	
	private IKryptelComponent hmacComp;
	private IMacSetup hmacSetup;
	private IHashFunctionParams hmacParams;
	private IHashFunction hmacFunc;
	
	private IKryptelComponent compressorComp;
	private ICompressorParams compressorParams;
	private IMemoryBlockCompressor blockCompressor;
	private ICompressor streamCompressor;

	private IKryptelComponent cipherComp;
	private IBlockCipherParams cipherParams;
	private IRawBlockCipher rawBlockCipher;
	private ICipher streamCipher;
	
	
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
	
	
	private void WriteHeader() throws Exception {
		int verCounts = VERIFICATION_LOOP_COUNT;
		byte[] keyVerificator = ComputeVerificator(verCounts);	// Uses HMAC so must be called before hmacFunc.Init()

		hmacFunc.Init();
		parcelMD5.reset();
		
		int tag = PARCEL_TAG;
		Store(Write, tag);
		short ver = ENGINE_VERSION_CREATED;
		Store(Write, ver);
		ver = EXTRACTOR_VERSION_REQUIRED;
		Store(Write, ver);
		
		Store(Write, Conversions.UuidToBytes(CID_SILVER_KEY));
		Store(Write, Conversions.UuidToBytes(parcelGuid));
		Store(Write, parcelFlags);
		
		Store(Write, Conversions.UuidToBytes(cipherComp.ComponentID()));
		int[] params = new int [5];
		params[0] = cipherParams.GetKeySize();
		params[1] = cipherParams.GetBlockSize();
		params[2] = cipherParams.GetRounds();
		params[3] = cipherParams.GetScheme();
		params[4] = cipherParams.GetChainingMode();
		byte[] bparams = new byte [20];
		Conversions.ToBytes(bparams, 0, params, 0, 20);
		Store(Write, bparams);
		
		Store(Write, Conversions.UuidToBytes(keyRecord.keyMaterial));
		Store(Write, verCounts);
		Store(Write, keyVerificator);
		
		byte[] encVector = new byte [cipherParams.GetBlockSize()];
		rawBlockCipher.DecryptBlock(encVector, 0, initVector, 0);
		Store(Write, encVector);
		
		Store(Write, cipherComp.ComponentName());
		CipherInfo info = cipherParams.GetInfo();
		Store(Write, info.Schemes[cipherParams.GetScheme() - 1]);

		Store(Write, parcelTitle);
		
		if ((parcelFlags & SK_FLAG_SHOW_DESCRIPTION) != 0) {
			assert (parcelDescription != null && !parcelDescription.isEmpty());
			Store(Write, (int)parcelDescription.length());
			byte[] comprDescr = blockCompressor.CompressWideString(parcelDescription);
			Store(Write, (int)comprDescr.length);
			Store(Write, comprDescr);
		}
		
		headerHmac = hmacFunc.Done();
	}
	
	
	private void WriteParcelData() throws Exception {
		hmacFunc.Init();
		
		if (progressCallback != null && nFiles > 0) progress = new Progress(progressCallback, callbackArg, (nFiles > 1) ? uTotalBytes : 0);
		
		for (Element e: script) e.StoreElement();
		
		if (progress != null) {
			progress.Discard();
			progress = null;
		}
		
		if ((compCapabilities & CAP_SMALL_PARCEL_OBFUSCATION) != 0 && (currentPos - fileAreaOffset) < FILE_AREA_OBFUSCATION_THRESHOLD) {
			int obfLen = FILE_AREA_OBFUSCATION_THRESHOLD + (rand.nextInt() & 0x7FFFFFFF) % FILE_AREA_OBFUSCATION_THRESHOLD;
			byte[] obfData = new byte [obfLen];
			rand.nextBytes(obfData);
			Store(Write, obfData);
		}
		
		fileAreaHmac = hmacFunc.Done();
	}
	

	private void WriteParcelScript() throws Exception {
		hmacFunc.Init();

		cipherParams.SetInitVector(initVector, 0, initVector.length);

		compressorParams.SetLevel(CT_MAX_COMPRESSION);
		CompressSink sink = new CompressSink();
		streamCompressor.Init(sink, null);
		
		int tag = COMMAND_PROGRESS;
		Store(EncryptAndWrite, tag);
		Store(EncryptAndWrite, nDirectories);
		Store(EncryptAndWrite, nFiles);
		Store(EncryptAndWrite, uTotalBytes);
		
		for (Element e: script) e.StoreCommand();

		tag = COMMAND_NULL;					// Mark end of stream
		Store(EncryptAndWrite, tag);
		
		if ((compCapabilities & CAP_SMALL_PARCEL_OBFUSCATION) != 0 && (currentPos - scriptAreaOffset) < SCRIPT_AREA_OBFUSCATION_THRESHOLD) {
			int obfLen = SCRIPT_AREA_OBFUSCATION_THRESHOLD + (rand.nextInt() & 0x7FFFFFFF) % SCRIPT_AREA_OBFUSCATION_THRESHOLD;
			byte[] obfData = new byte [obfLen];
			rand.nextBytes(obfData);
			Store(EncryptAndWrite, obfData);
		}
		
		streamCompressor.Done();
		scriptAreaHmac = hmacFunc.Done();
	}
	
	
	private void CleanUp() throws Exception {
		if (dataSink != null) {
			if (dataSinkInitialized) dataSink.Done();
			dataSink = null;
			dataSinkArg = null;
		}
	
		cipherComp = null;
		cipherParams = null;
		rawBlockCipher = null;
		streamCipher = null;
		
		parcelMD5.reset();
		
		IComponentState state = (IComponentState)hmacComp.GetInterface(IID_IComponentState);
		state.Reset();
		state = (IComponentState)compressorComp.GetInterface(IID_IComponentState);
		state.Reset();
		
		if (keyRecord != null) {
			Arrays.fill(keyRecord.keyData, (byte)0);
			keyRecord = null;
		}
		
		if (initVector != null) {
			Arrays.fill(initVector, (byte)0);
			initVector = null;
		}

		parcelTitle = defaultParcelTitle;
		parcelDescription = null;
		
		if (progress != null) {
			progress.Discard();
			progress = null;
		}
	}

	
  //
  // Encryption and compression datasinks
  //

	private class EncryptSink implements IDataSink {
		public void Init(Object arg) throws Exception { }
		public void PutData(byte[] buf, int start, int size) throws Exception { Write.Out(buf, start, size); }
		public void Done() throws Exception { }
	}

	private class CompressSink implements IDataSink {
		public void Init(Object arg) throws Exception { streamCipher.Init(new EncryptSink(), null); }
		public void PutData(byte[] buf, int start, int size) throws Exception { streamCipher.Encrypt(buf, start, size); }
		public void Done() throws Exception { streamCipher.Done(); }
	}
	
	
	private interface IDataOut {
		void Out(byte[] buf, int start, int size) throws Exception;
	}
	
	IDataOut Write = new IDataOut() {
		public void Out(byte[] buf, int start, int size) throws Exception {
			dataSink.PutData(buf, start, size);
			hmacFunc.Hash(buf, start, size);
			parcelMD5.update(buf, start, size);
			currentPos += size;
		}
	};
	
	IDataOut WriteNoHmac = new IDataOut() {
		public void Out(byte[] buf, int start, int size) throws Exception {
			dataSink.PutData(buf, start, size);
			parcelMD5.update(buf, start, size);
			currentPos += size;
		}
	};
	
	IDataOut PureWrite = new IDataOut() {
		public void Out(byte[] buf, int start, int size) throws Exception {
			dataSink.PutData(buf, start, size);
			currentPos += size;
		}
	};

	IDataOut EncryptAndWrite = new IDataOut() {
		public void Out(byte[] buf, int start, int size) throws Exception {
			streamCompressor.Compress(buf, start, size);
		}
	};
	
	// Output helper functions
	
	private byte[] storeBuffer = new byte [8];		// Buffer for Store functions
	
	private void Store(IDataOut outFunc, byte[] buf) throws Exception { outFunc.Out(buf, 0, buf.length); }
	
	//private void Store(IDataOut outFunc, byte[] buf, int start, int size) throws Exception { outFunc.Out(buf, start, size); }
	
	//private void Store(IDataOut outFunc, byte b) throws Exception { storeBuffer[0] = b; outFunc.Out(storeBuffer, 0, 1); }
	
	private void Store(IDataOut outFunc, short sh) throws Exception { storeBuffer[0] = (byte)sh; storeBuffer[1] = (byte)(sh >>> 8); outFunc.Out(storeBuffer, 0, 2); }
	
	private void Store(IDataOut outFunc, int i) throws Exception {
		storeBuffer[0] = (byte)i;
		storeBuffer[1] = (byte)(i >>> 8);
		storeBuffer[2] = (byte)(i >>> 16);
		storeBuffer[3] = (byte)(i >>> 24);
		outFunc.Out(storeBuffer, 0, 4);
	}
	
	private void Store(IDataOut outFunc, long l) throws Exception {
		storeBuffer[0] = (byte)l;
		storeBuffer[1] = (byte)(l >>> 8);
		storeBuffer[2] = (byte)(l >>> 16);
		storeBuffer[3] = (byte)(l >>> 24);
		storeBuffer[4] = (byte)(l >>> 32);
		storeBuffer[5] = (byte)(l >>> 40);
		storeBuffer[6] = (byte)(l >>> 48);
		storeBuffer[7] = (byte)(l >>> 56);
		outFunc.Out(storeBuffer, 0, 8);
	}
	
	private void Store(IDataOut outFunc, String str) throws Exception {
		Store(outFunc, (short)str.length());
		byte[] byteSeq = str.getBytes("UnicodeLittleUnmarked");
		Store(outFunc, byteSeq);
	}
}
