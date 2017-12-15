/*******************************************************************************

  Product:       Kryptel/Java
  File:          Agent.java
 
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
import static com.kryptel.Constants.*;
import static com.kryptel.Guids.*;
import static com.kryptel.bslx.Conversions.*;
import static com.kryptel.storage.Kryptel.*;

import java.util.UUID;

import com.kryptel.IComponentCapabilities;
import com.kryptel.IComponentState;
import com.kryptel.IKeyCallback;
import com.kryptel.IKryptelComponent;
import com.kryptel.Loader;
import com.kryptel.Message;
import com.kryptel.cipher.CipherParameters;
import com.kryptel.compressor.CompressorParameters;
import com.kryptel.hash_function.HashFunctionParameters;
import com.kryptel.storage.IEncryptedStorage.CONTAINER_COMPRESSION_STRATEGY;


abstract class Agent implements IKryptelComponent, IComponentCapabilities, IComponentState, IEncryptedFileStorage, IEncryptedFileStorageInfo {
	Agent(long capabilities) throws Exception {
		compCapabilities = capabilities;
	}
	
	
	//
	// IKryptelComponent
	//
	
	
	public Object GetInterface(UUID iid) {
		if (iid.equals(IID_IKryptelComponent) || iid.equals(IID_IComponentCapabilities) || iid.equals(IID_IComponentState)) return this;
		if (iid.equals(IID_IEncryptedFileStorage)) return this;
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

	
	public ComponentState GetState() throws Exception {
		if (storageComp != null) {
			IComponentState state = (IComponentState)storageComp.GetInterface(IID_IComponentState);
			return state.GetState();
		}
		else
			return ComponentState.ComponentIdle; }

	
	public void Reset() throws Exception {
		if (storageComp != null) {
			IComponentState state = (IComponentState)storageComp.GetInterface(IID_IComponentState);
			state.Reset();
		}
	}

	
	public IKryptelComponent Clone() throws Exception {
		return Loader.CreateComponent(ComponentID(), compCapabilities);
	}
	
	
	//
	// AutoCloseable
	//

	
	public void close() throws Exception { DiscardComponent(); }
	
	
	//
	// IEncryptedFileStorage
	//

	
	public IEncryptedFileStorageInfo GetFileStorageInfo() {
		return this;
	}
	
	
	public int SetStorageControlFlags(int scFlags) {
		int oldFlags = storageControlFlags;
		storageControlFlags = scFlags;
		return oldFlags;
	}
	
	
	public CONTAINER_COMPRESSION_STRATEGY SetCompressionStrategy(CONTAINER_COMPRESSION_STRATEGY strategy) throws Exception {
		if (storageComp != null) throw new Exception("Agent::SetCompressionStrategy : Container already open.");
		CONTAINER_COMPRESSION_STRATEGY prevStrategy = compressionStrategy;
		compressionStrategy = strategy;
		return prevStrategy;
	}
	

	public void SetDescription(String descr) throws Exception {
		if (storageComp == null) throw new Exception("Agent::SetDescription : Container is not open.");
		if (descr != null) {
			byte[] byteSeq = descr.getBytes("UnicodeLittleUnmarked");
			// String must be zero-delimited
			byte[] zd = new byte [byteSeq.length + 2];
			System.arraycopy(byteSeq, 0, zd, 0, byteSeq.length);
			zd[byteSeq.length] = zd[byteSeq.length + 1] = (byte)0;
			storage.SetAgentData(zd, 0, zd.length);
		}
		else
			storage.SetAgentData(null, 0, 0);
	}

	
	public String GetEncryptedDescription() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetEncryptedDescription : Container is not open.");
		if (!rootObject.StreamExists()) return null;
		
		int size = (int)rootObject.StreamSize();
		// String is zero-delimited
		if (size <= 2) return "";
		
		byte[] byteSeq = new byte [size - 2];
		IEncryptedStream stream = null;
		try {
			stream = rootObject.OpenStream();
			stream.Read(byteSeq, 0, size - 2);
		}
		finally {
			if (stream != null) stream.Close();
		}
		
		return new String(byteSeq, 0, byteSeq.length, "UnicodeLittleUnmarked");
	}
	
	
	public void SetEncryptedDescription(String descr) throws Exception {
		if (storageComp == null) throw new Exception("Agent::SetEncryptedDescription : Container is not open.");
		if (!rootObject.StreamExists()) rootObject.DeleteStream();
		
		if (descr == null || descr.isEmpty()) return;
		
		byte[] byteSeq = descr.getBytes("UnicodeLittleUnmarked");

		IEncryptedStream stream = null;
		try {
			stream = rootObject.CreateStream(CT_MAX_COMPRESSION);
			stream.Write(byteSeq, 0, byteSeq.length);
			stream.Write(ShortAsBytes((short)0), 0, 2);
		}
		finally {
			if (stream != null) stream.Close();
		}
	}
	
	
	public void Create(String path, IKryptelComponent cipher, IKryptelComponent compressor, IKryptelComponent hashFunc, UUID handler, Object keyArg, IKeyCallback keyFunc) throws Exception {
		if (storageComp != null) throw new Exception("Agent::Create : Container already open.");

		storageComp = Loader.CreateComponent(handler, compCapabilities);
		if (storageComp == null) throw new Exception(Message.Get(Message.Code.EncryptorNotFound));
		
		try {
			storage = (IEncryptedStorage)storageComp.GetInterface(IID_IEncryptedStorage);
			if (storage == null) throw new Exception("Agent::Create : Unable to obtain IEncryptedStorage.");

			storage.SetCompressionStrategy(compressionStrategy);
			rootObject = storage.Create(path, cipher, compressor, hashFunc, ComponentID(), keyArg, keyFunc);
			
			IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
			int cap = storageInfo.GetStorageCapabilities();
			bRecoveryBlocks = (compCapabilities & CAP_RECOVERY_BLOCKS) != 0 && (cap & ESTOR_RECOVERY_BLOCKS) != 0;
			
			keyFilePath = storageInfo.GetKeyPath();
		}
		catch (Exception e) {
			storageComp.DiscardComponent();
			storageComp = null;
			throw e;
		}
	}
	
	
	public void Open(String path, IEncryptedStorage.CONTAINER_ACCESS_MODE mode, Object keyArg, IKeyCallback keyFunc) throws Exception {
		if (storageComp != null) throw new Exception("Agent::Open : Container already open.");

		ContainerHandlers ch = GetContainerHandlers(path);
		if (ch == null) throw new Exception("Agent::Open : Not a valid container.");
		if (!ch.agent.equals(ComponentID())) throw new Exception("Agent::Open : Attempt to open container using a wrong agent.");
		
		storageComp = Loader.CreateComponent(ch.storage, compCapabilities);
		if (storageComp == null) throw new Exception(Message.Get(Message.Code.EncryptorNotFound));

		try {
			storage = (IEncryptedStorage)storageComp.GetInterface(IID_IEncryptedStorage);
			if (storage == null) throw new Exception("Agent::Open : Unable to obtain IEncryptedStorage.");

			storage.SetCompressionStrategy(compressionStrategy);
			rootObject = storage.Open(path, mode, keyArg, keyFunc);

			IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
			int cap = storageInfo.GetStorageCapabilities();
			bRecoveryBlocks = (compCapabilities & CAP_RECOVERY_BLOCKS) != 0 && (cap & ESTOR_RECOVERY_BLOCKS) != 0;
			
			keyFilePath = storageInfo.GetKeyPath();
		}
		catch (Exception e) {
			storageComp.DiscardComponent();
			storageComp = null;
			throw e;
		}
	}
	
	
	public void Close() throws Exception {
		if (storageComp != null) {
			storage.Close();
			storageComp.DiscardComponent();
			storageComp = null;
		}
	}
	
	
	public void Compress() throws Exception {
		if (storageComp != null) {
			storage.Compress();
			storageComp.DiscardComponent();
			storageComp = null;
		}
	}
	
	
	public void Discard() throws Exception {
		if (storageComp != null) {
			storage.Discard();
			storageComp.DiscardComponent();
			storageComp = null;
		}
	}

	
	//
	// IEncryptedStorageInfo
	//


	public int GetStorageCapabilities() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetStorageCapabilities : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetStorageCapabilities();
	}
	
	public StorageStatistics GetStorageStatistics() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetStorageStatistics : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetStorageStatistics();
	}
	
	public byte[] GetAgentData() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetAgentData : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetAgentData();
	}
	
	public UUID GetCipherCID() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetCipherCID : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetCipherCID();
	}
	
	public CipherParameters GetCipherParameters() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetCipherParameters : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetCipherParameters();
	}
	
	public String GetCipherName()  throws Exception{
		if (storageComp == null) throw new Exception("Agent::GetCipherName : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetCipherName();
	}
	
	public String GetCipherScheme() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetCipherScheme : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetCipherScheme();
	}
	
	public UUID GetCompressorCID() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetCompressorCID : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetCompressorCID();
	}
	
	public CompressorParameters GetCompressorParameters() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetCompressorParameters : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetCompressorParameters();
	}
	
	public String GetCompressorName() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetCompressorName : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetCompressorName();
	}
	
	public String GetCompressorScheme() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetCompressorScheme : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetCompressorScheme();
	}
	
	public UUID GetHashFunctionCID() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetHashFunctionCID : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetHashFunctionCID();
	}
	
	public HashFunctionParameters GetHashFunctionParameters() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetHashFunctionParameters : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetHashFunctionParameters();
	}
	
	public String GetHashFunctionName() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetHashFunctionName : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetHashFunctionName();
	}
	
	public String GetHashFunctionScheme() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetHashFunctionScheme : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetHashFunctionScheme();
	}
	
	public UUID GetKeyID() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetKeyID : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetKeyID();
	}
	
	public String GetKeyPath() throws Exception {
		if (storageComp == null) throw new Exception("Agent::GetKeyPath : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.GetKeyPath();
	}
	
	
	public boolean TestPassword(String password) throws Exception {
		if (storageComp == null) throw new Exception("Agent::TestPassword : Container is not open.");
		IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
		return storageInfo.TestPassword(password);
	}
	
	
	//
	// IEncryptedFileStorageInfo
	//

	
	public long GetFileStorageCapabilities() throws Exception {
		long cap = EFSTOR_DESCRIPTIONS | EFSTOR_ENCRYPTED_DESCRIPTIONS | EFSTOR_KEYWORDS | EFSTOR_ITEM_DESCRIPTIONS | EFSTOR_FILE_STORAGE_STATISTICS;
		if (ComponentID().equals(CID_BACKUP_AGENT)) cap |= EFSTOR_TARGETS | EFSTOR_ASSOCIATED_DATA;
		if (storageComp != null) {
			IEncryptedStorageInfo storageInfo = storage.GetStorageInfo();
			assert storageInfo != null;
			cap |= (long)storageInfo.GetStorageCapabilities() & 0x00000000FFFFFFFFL;
		}
		return cap;
	}
	
	
	public String GetDescription() throws Exception {
		byte[] byteDescr = GetAgentData();
		return (byteDescr != null && byteDescr.length > 2) ? new String(byteDescr, 0, byteDescr.length - 2, "UnicodeLittleUnmarked") : null;
	}
	
	
  //
  // Private data and methods
  //

	
	private CONTAINER_COMPRESSION_STRATEGY compressionStrategy = IEncryptedStorage.DEFAULT_COMPRESSION_STRATEGY;

  protected long compCapabilities = CAP_DEFAULT_CAPABILITIES;

	protected IKryptelComponent storageComp;
	protected IEncryptedStorage storage;
	protected IEncryptedObject rootObject;
	
	int storageControlFlags = FSCF_DEFAULT;
	protected boolean bRecoveryBlocks;
	
	protected String keyFilePath;
	
	byte[] ioBuffer = new byte [DEFAULT_BUFFER_SIZE];
	
	
	abstract DirectoryObject FindDirectoryObject(IEncryptedDirectory encDir) throws Exception;
	
	protected abstract boolean IsBackupAgent();
}
