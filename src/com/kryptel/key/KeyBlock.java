/*******************************************************************************

  Product:       Kryptel/Java
  File:          KeyBlock.java
  Description:   https://www.kryptel.com/articles/developers/java/key.key.keyblock.php

  Copyright (c) 2018 Inv Softworks LLC,    http://www.kryptel.com

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


package com.kryptel.key;


import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.UUID;

import com.kryptel.IKryptelComponent;
import com.kryptel.Loader;
import com.kryptel.bslx.IntRef;
import com.kryptel.bslx.SmartBuffer;
import com.kryptel.cipher.IBlockCipher;
import com.kryptel.cipher.IBlockCipherParams;
import com.kryptel.hash_function.IHashFunction;
import com.kryptel.hash_function.IHashFunctionParams;

import static com.kryptel.Constants.*;
import static com.kryptel.Guids.*;
import static com.kryptel.key.KeyUtils.*;


public class KeyBlock {
	
	public final static int SALT_SIZE					= 8;
	
	// Key IDs
	
	public final static byte KEY_LEVEL_0			= (byte)0;
	public final static byte KEY_LEVEL_3			= (byte)(3 << 5);
	public final static byte KEY_LEVEL_5			= (byte)(5 << 5);
	
	public final static byte KEY_PASSWORD			= (byte)(0x01 | KEY_LEVEL_0);
	public final static byte KEY_BINARY_KEY		= (byte)(0x05 | KEY_LEVEL_0);
	public final static byte KEY_COMPOSITE		= (byte)(0x0F | KEY_LEVEL_3);
	public final static byte KEY_GROUP				= (byte)(0x1C | KEY_LEVEL_5);

	// Allowed / expected key material

	public final static byte KEY_MATERIAL_PASSWORD			= (byte)0x01;
	public final static byte KEY_MATERIAL_BINARY_KEY		= (byte)0x02;
	public final static byte KEY_MATERIAL_YUBIKEY				= (byte)0x04;
	public final static byte KEY_MATERIAL_COMPOSITE			= (byte)0x10;
	public final static byte KEY_MATERIAL_GROUP					= (byte)0x20;
	public final static byte KEY_MATERIAL_EVERYTHING		= (byte)0x7F;

	public final static byte KEY_MATERIAL_MATCHED				= (byte)0x00;		// Matched successfully, no more key material expected
	public final static byte KEY_MATERIAL_FAILED				= (byte)0x80;		// Highest bit is set if matching failed; bits 0x7F specify expected material

	
	//
	//Password/key flags 
	//
	
	public final static byte PASSWORD_CAN_CREATE				= (byte)0x01;
	public final static byte PASSWORD_CAN_MODIFY				= (byte)0x02;
	public final static byte PASSWORD_CAN_DECRYPT				= (byte)0x04;
	public final static byte PASSWORD_MASTER_KEY				= (byte)0x80;
	
	public final static byte PASSWORD_DEFAULT_FLAGS			= (byte)(PASSWORD_CAN_CREATE | PASSWORD_CAN_MODIFY | PASSWORD_CAN_DECRYPT);

	
	public final static class ComponentDescriptor {
		public UUID hashFunction;
		public int hashSize;
		public int hashPasses;
		public byte hashScheme;
		
		public UUID cipher;
		public int cipherKeySize;
		public int cipherBlockSize;
		public int cipherRounds;
		public byte cipherScheme;
	}
	
	
	//**********************************************************************
	//*** Key classes - Key (abstract ancestor)
	
	
	protected abstract class Key {
		
		protected Key(byte id, boolean loaded, byte flags) {
			this.loaded = loaded;
			this.keyID = id;
			this.flags = flags;
		}
			
		
		protected byte GetID() { return keyID; }
		protected byte GetFlags() { return flags; }
		protected boolean IsLoaded() { return loaded; }
			
		
		protected byte[] GetBaseKey() throws Exception {
			if (!IsMatched()) throw new Exception("Key : Base key is not available (not matched).");
			assert key != null;
			return key;
		}
			
		
		protected abstract byte Expected();
		protected abstract boolean IsMatched();
		protected abstract byte KeyMaterial();
			
		
		protected byte MatchPassword(String password) throws Exception {
			if (!loaded) throw new Exception("Key : Can't match fully defined (not loaded) password.");
			return Expected();
		}
		
		
		protected byte MatchBinaryKey(byte[] binaryKey) throws Exception {
			if (!loaded) throw new Exception("Key : Can't match fully defined (not loaded) binary key.");
			return Expected();
		}
			
		
		protected void StoreKey(SmartBuffer buffer) throws Exception {
			if (loaded) throw new Exception("Key : Can't store loaded key.");
			byte b[] = new byte [2];
			b[0] = keyID;
			b[1] = flags;
			buffer.Store(b);
		}
		
		
		protected void CleanUp() throws Exception {
			keyID = 0;
			flags = 0;
			if (key != null) Arrays.fill(key, (byte)0);
		}
		
		
		protected final boolean loaded;
		protected byte keyID;
		protected byte flags;
		protected byte[] key;
			
		protected abstract void ComputeBaseKey() throws Exception;
	}
	
	
	//**********************************************************************
	//*** Key classes - Password
	
	
	public class Password extends Key {
		
		public Password(String password, byte flags) throws Exception {
			super(KEY_PASSWORD, false, flags);
			
			assert password != null;
			this.password = password.trim().replaceAll("[\t\n\f\r]", " ").replaceAll(" {2,}", " ");
			if (this.password.isEmpty()) throw new Exception("Password : Password is empty.");

			verificator = ComputePasswordVerificator(hashFunc, descr.hashSize, salt, this.password);
			
			ComputeBaseKey();
		}
		
		
		protected Password(byte[] keyRecord, IntRef start) {
			super(KEY_PASSWORD, true, (byte)0);
			flags = keyRecord[start.val++];
			verificator = Arrays.copyOfRange(keyRecord, start.val, start.val + descr.hashSize);
			start.val += verificator.length;
		}
			
		
		protected byte Expected() { return IsMatched() ? KEY_MATERIAL_MATCHED : KEY_MATERIAL_PASSWORD; }
		protected boolean IsMatched() { return password != null; }
		protected byte KeyMaterial() { return KEY_MATERIAL_PASSWORD; }
			
		
		protected byte MatchPassword(String password) throws Exception {
			byte ret = super.MatchPassword(password);
			if (ret == KEY_MATERIAL_MATCHED || (ret & KEY_MATERIAL_FAILED) != 0) return ret;
			
			assert password != null;
			String pwd = password.trim().replaceAll("[\t\n\f\r]", " ").replaceAll(" {2,}", " ");
			if (pwd.isEmpty()) throw new Exception("Password : Password is empty.");

			if (Arrays.equals(verificator, ComputePasswordVerificator(hashFunc, descr.hashSize, salt, pwd))) {
				this.password = pwd;
				ComputeBaseKey();
				return KEY_MATERIAL_MATCHED;
			}
			else
				return KEY_MATERIAL_FAILED | KEY_MATERIAL_PASSWORD;
		}
		
		
		protected byte MatchBinaryKey(byte[] binaryKey) throws Exception {
			return super.MatchBinaryKey(binaryKey);
		}
			
		
		protected void StoreKey(SmartBuffer buffer) throws Exception {
			super.StoreKey(buffer);
			buffer.Store(verificator);
		}
		
		
		protected void ComputeBaseKey() throws Exception {
			if (password == null) throw new Exception("Password : Password is NULL.");

			if (key == null) key = new byte [descr.hashSize];
			
			hashFunc.Init();
			hashFunc.Hash(salt, 0, salt.length);
			byte[] byteSeq = password.getBytes("UnicodeLittleUnmarked");
			hashFunc.Hash(byteSeq, 0, byteSeq.length);
			key = hashFunc.Done();
		}

		
		protected void CleanUp() throws Exception {
			super.CleanUp();
			Arrays.fill(verificator, (byte)0);
		}
		
		
		private String password;
		private byte[] verificator;
	}
	
	
	//**********************************************************************
	//*** Key classes - BinaryKey


	public class BinaryKey extends Key {
		
		public BinaryKey(byte[] binaryKey, byte flags) throws Exception {
			super(KEY_BINARY_KEY, false, (byte)flags);
			this.binaryKey = Arrays.copyOf(binaryKey, BINARY_KEY_SIZE);
			verificator = ComputeBinaryKeyVerificator(hashFunc, descr.hashSize, salt, this.binaryKey);
			ComputeBaseKey();
		}
		
		
		protected BinaryKey(byte[] keyRecord, IntRef start) {
			super(KEY_BINARY_KEY, true, (byte)0);
			flags = keyRecord[start.val++];
			verificator = Arrays.copyOfRange(keyRecord, start.val, start.val + descr.hashSize);
			start.val += verificator.length;
		}
		
		
		protected byte Expected() { return IsMatched() ? KEY_MATERIAL_MATCHED : KEY_MATERIAL_BINARY_KEY; }
		protected boolean IsMatched() { return binaryKey != null; }
		protected byte KeyMaterial() { return KEY_MATERIAL_BINARY_KEY; }
		
		
		protected byte MatchPassword(String password) throws Exception {
			return super.MatchPassword(password);
		}
		
		
		protected byte MatchBinaryKey(byte[] binaryKey) throws Exception {
			byte ret = super.MatchBinaryKey(binaryKey);
			if (ret == KEY_MATERIAL_MATCHED || (ret & KEY_MATERIAL_FAILED) != 0) return ret;

			assert binaryKey != null;
			byte bk[] = Arrays.copyOf(binaryKey, BINARY_KEY_SIZE);
			if (Arrays.equals(verificator, ComputeBinaryKeyVerificator(hashFunc, descr.hashSize, salt, bk))) {
				this.binaryKey = bk;
				ComputeBaseKey();
				return KEY_MATERIAL_MATCHED;
			}
			else
				return KEY_MATERIAL_FAILED | KEY_MATERIAL_BINARY_KEY;
		}
		
		
		protected void StoreKey(SmartBuffer buffer) throws Exception {
			super.StoreKey(buffer);
			buffer.Store(verificator);
		}
	
		
		protected void ComputeBaseKey() throws Exception {
			if (binaryKey == null) throw new Exception("BinaryKey : No binary key set.");
			
			if (key == null) key = new byte [descr.hashSize];
			
			hashFunc.Init();
			hashFunc.Hash(salt, 0, salt.length);
			hashFunc.Hash(binaryKey, 0, binaryKey.length);
			key = hashFunc.Done();
		}

		
		protected void CleanUp() throws Exception {
			super.CleanUp();
			Arrays.fill(binaryKey, (byte)0);
			Arrays.fill(verificator, (byte)0);
		}
	
		
		private byte[] binaryKey;
		private byte[] verificator;
	}
	
	
	//**********************************************************************
	//*** Key classes - ComplexKey (abstract ancestor for complex keys)
	
	
	public abstract class ComplexKey extends Key {
		
		protected ComplexKey(byte id, boolean loaded, byte flags) {
			super(id, loaded, flags);
		}
			
		
		public void AddSubkey(Key subkey) throws Exception {
			if (DecodeKeyLevel(subkey.GetID()) >= DecodeKeyLevel(GetID())) throw new Exception("ComplexKey.AddSubkey : Subkey level must be less than complex key level.");
			if (keyList.size() == 255) throw new Exception("AddSubkey : Too many subkeys.");
			keyList.add(subkey);
			ComputeBaseKey();
		}

		
		protected void CleanUp() throws Exception {
			super.CleanUp();
			for (Key k: keyList) k.CleanUp();
		}
		
		
		protected ArrayList<Key> keyList = new ArrayList<Key>();
	}


//**********************************************************************
//*** Key classes - CompositeKey


	public class CompositeKey extends ComplexKey {

		public CompositeKey(byte flags) {
			super(KEY_COMPOSITE, false, flags);
		}
		
		
		protected CompositeKey(byte[] keyRecord, IntRef start) throws Exception {
			super(KEY_COMPOSITE, true, (byte)0);
			flags = keyRecord[start.val++];
			int nKeys = keyRecord[start.val++];
			
			byte type;
			for (int i = 0; i < nKeys; i++) {
				type = keyRecord[start.val++];
				switch (type) {
					case KEY_PASSWORD:
						keyList.add(new Password(keyRecord, start));
						break;
						
					case KEY_BINARY_KEY:
						keyList.add(new BinaryKey(keyRecord, start));
						break;

					default:
						throw new Exception("CompositeKey : Unsupported subkey type.");
				}
			}
		}
		
		
		protected byte Expected() {
			byte exp = 0;
			for (Key k: keyList) exp |= k.Expected();
			return exp;
		}
		
		
		protected boolean IsMatched()  {
			return Expected() == KEY_MATERIAL_MATCHED;
		}
		
		
		protected byte KeyMaterial() {
			byte ret = KEY_MATERIAL_COMPOSITE;
			for (Key k: keyList) ret |= k.KeyMaterial();
			return ret;
		}
		
		
		protected byte MatchPassword(String password) throws Exception {
			byte ret = super.MatchPassword(password);
			if (ret == KEY_MATERIAL_MATCHED || (ret & KEY_MATERIAL_FAILED) != 0) return ret;
			
			for (Key k: keyList) {
				if (k.GetID() == KEY_PASSWORD		&&
						!k.IsMatched()							&&
						k.MatchPassword(password) == KEY_MATERIAL_MATCHED) {
					ComputeBaseKey();
					return Expected();
				}
			}
			
			return (byte)(Expected() | KEY_MATERIAL_FAILED);
		}
		
		
		protected byte MatchBinaryKey(byte[] binaryKey) throws Exception {
			byte ret = super.MatchBinaryKey(binaryKey);
			if (ret == KEY_MATERIAL_MATCHED || (ret & KEY_MATERIAL_FAILED) != 0) return ret;
			
			for (Key k: keyList) {
				if (k.GetID() == KEY_BINARY_KEY		&&
						!k.IsMatched()								&&
						k.MatchBinaryKey(binaryKey) == KEY_MATERIAL_MATCHED) {
					ComputeBaseKey();
					return Expected();
				}
			}
			
			return (byte)(Expected() | KEY_MATERIAL_FAILED);
		}
		
		
		protected void StoreKey(SmartBuffer buffer) throws Exception {
			super.StoreKey(buffer);
			byte b[] = { (byte)keyList.size() };
			buffer.Store(b);
			for (Key k: keyList) k.StoreKey(buffer);
		}

		
		protected void ComputeBaseKey() throws Exception {
			if (!IsMatched()) return;
			
			if (key == null) key = new byte [descr.hashSize];
			Arrays.fill(key, (byte)0);
			
			for (Key k: keyList) {
				byte[] bk = k.GetBaseKey();
				for (int i = 0; i < descr.hashSize; i++) key[i] ^= bk[i];
			}
		}
	}


	//**********************************************************************
	//*** Key classes - GroupKey


	public class GroupKey extends ComplexKey {
		
		public GroupKey() throws Exception {
			super(KEY_GROUP, false, (byte)0);
			
			cipherComp = Loader.CreateComponent(descr.cipher);
			if (cipherComp == null) throw new Exception("Requested cipher not found.");
			cipherParams = (IBlockCipherParams)cipherComp.GetInterface(IID_IBlockCipherParams);
			cipher = (IBlockCipher)cipherComp.GetInterface(IID_IBlockCipher);
			
			cipherParams.SetKeySize(descr.cipherKeySize);
			cipherParams.SetBlockSize(descr.cipherBlockSize);
			cipherParams.SetRounds(descr.cipherRounds);
			cipherParams.SetScheme(descr.cipherScheme);
			cipherParams.SetChainingMode(IBlockCipherParams.MODE_ECB);
			
			encryptedKeySize = descr.hashSize + descr.cipherBlockSize - 1;
			encryptedKeySize /= descr.cipherBlockSize;
			encryptedKeySize *= descr.cipherBlockSize;
		}
		
		
		protected GroupKey(byte[] keyRecord, IntRef start) throws Exception {
			super(KEY_GROUP, true, (byte)0);
			
			cipherComp = Loader.CreateComponent(descr.cipher);
			if (cipherComp == null) throw new Exception("Requested cipher not found.");
			cipherParams = (IBlockCipherParams)cipherComp.GetInterface(IID_IBlockCipherParams);
			cipher = (IBlockCipher)cipherComp.GetInterface(IID_IBlockCipher);
			
			cipherParams.SetKeySize(descr.cipherKeySize);
			cipherParams.SetBlockSize(descr.cipherBlockSize);
			cipherParams.SetRounds(descr.cipherRounds);
			cipherParams.SetScheme(descr.cipherScheme);
			cipherParams.SetChainingMode(IBlockCipherParams.MODE_ECB);
			
			encryptedKeySize = descr.hashSize + descr.cipherBlockSize - 1;
			encryptedKeySize /= descr.cipherBlockSize;
			encryptedKeySize *= descr.cipherBlockSize;

			flags = keyRecord[start.val++];
			int nKeys = keyRecord[start.val++];
			
			byte type;
			for (int i = 0; i < nKeys; i++) {
				type = keyRecord[start.val++];
				switch (type) {
					case KEY_PASSWORD:
						keyList.add(new Password(keyRecord, start));
						break;
						
					case KEY_BINARY_KEY:
						keyList.add(new BinaryKey(keyRecord, start));
						break;
						
					case KEY_COMPOSITE:
						keyList.add(new CompositeKey(keyRecord, start));
						break;

					default:
						throw new Exception("GroupKey : Unsupported subkey type.");
				}
				
				encryptedKeys.add(Arrays.copyOfRange(keyRecord, start.val, start.val + encryptedKeySize));
				start.val += encryptedKeySize;
			}
		}
			
			
		protected byte Expected() {
			byte exp = 0;
			for (Key k: keyList) exp |= k.Expected();
			return exp;
		}
			
			
		protected boolean IsMatched() {
			for (Key k: keyList) {
				if (k.Expected() == KEY_MATERIAL_MATCHED) return true;
			}
			return false;
		}
		
		
		protected byte KeyMaterial() {
			byte ret = KEY_MATERIAL_GROUP;
			for (Key k: keyList) ret |= k.KeyMaterial();
			return ret;
		}
		
		
		protected boolean IsFullyMatched() {
			for (Key k: keyList) {
				if (k.Expected() != KEY_MATERIAL_MATCHED) return false;
			}
			return true;
		}
		
		
		protected boolean IsForged() throws Exception {
			assert IsFullyMatched();
			byte[] decryptedKey = Arrays.copyOf(GetBaseKey(), descr.hashSize);
			ComputeBaseKey();
			return !Arrays.equals(decryptedKey, GetBaseKey());
		}
		
		
		public void AddSubkey(Key subkey) throws Exception {
			super.AddSubkey(subkey);
			flags |= subkey.GetFlags();
		}
		
		
		protected byte MatchPassword(String password) throws Exception {
			byte exp, ret;
			super.MatchPassword(password);
			
			ret = KEY_MATERIAL_FAILED;

			for (int i = 0; i < keyList.size(); i++) {
				if (keyList.get(i).IsMatched()) continue;

				if (keyList.get(i).GetID() == KEY_PASSWORD || keyList.get(i).GetID() == KEY_COMPOSITE) {
					exp =keyList.get(i).MatchPassword(password);
					if (exp == KEY_MATERIAL_MATCHED) {
						while (encryptedKeys.size() <= i) encryptedKeys.add(new byte [encryptedKeySize]);
						DecryptSessionKey(keyList.get(i).GetBaseKey(), encryptedKeys.get(i));
						UpdateFlags();
						return KEY_MATERIAL_MATCHED;
					}
					
					// May be matched, but matching is not complete yet
					if ((exp & KEY_MATERIAL_FAILED) == 0) ret &= ~KEY_MATERIAL_FAILED;	// Part of composite key matched, clear 'failed' bit
					ret |= exp & ~KEY_MATERIAL_FAILED;	// Build mask for expected key material
				}
				else
					ret |= keyList.get(i).Expected();
			}

			return ret;
		}
		
		
		protected byte MatchBinaryKey(byte[] binaryKey) throws Exception {
			byte exp, ret;
			super.MatchBinaryKey(binaryKey);
			
			ret = KEY_MATERIAL_FAILED;

			for (int i = 0; i < keyList.size(); i++) {
				if (keyList.get(i).IsMatched()) continue;

				if (keyList.get(i).GetID() == KEY_BINARY_KEY || keyList.get(i).GetID() == KEY_COMPOSITE) {
					exp = keyList.get(i).MatchBinaryKey(binaryKey);
					if (exp == KEY_MATERIAL_MATCHED) {
						while (encryptedKeys.size() <= i) encryptedKeys.add(new byte [encryptedKeySize]);
						DecryptSessionKey(keyList.get(i).GetBaseKey(), encryptedKeys.get(i));
						UpdateFlags();
						return KEY_MATERIAL_MATCHED;
					}
					
					// May be matched, but matching is not complete yet
					if ((exp & KEY_MATERIAL_FAILED) == 0) ret &= ~KEY_MATERIAL_FAILED;	// Part of composite key matched, clear 'failed' bit
					ret |= exp & ~KEY_MATERIAL_FAILED;	// Build mask for expected key material
				}
				else
					ret |= keyList.get(i).Expected();
			}

			return ret;
		}
		
			
		protected void StoreKey(SmartBuffer buffer) throws Exception {
			super.StoreKey(buffer);
			
			byte b[] = { (byte)keyList.size() };
			buffer.Store(b);
			
			for (Key k: keyList) {
				k.StoreKey(buffer);
				
				// Encrypt and store session key
				byte[] encryptedKey = new byte [encryptedKeySize];
				if (key.length < encryptedKeySize) rand.nextBytes(encryptedKey);
				System.arraycopy(key, 0, encryptedKey, 0, key.length);
				
				cipherParams.SetKey(k.GetBaseKey(), 0, descr.hashSize);
				
				cipher.Init();
				cipher.Encrypt(encryptedKey, 0, encryptedKeySize);
				cipher.Done();
				
				buffer.Store(encryptedKey, 0, encryptedKeySize);
			}
		}
		
			
		public void AddKeysFrom(GroupKey fromGroup) throws Exception {
			if (loaded || fromGroup.loaded) throw new Exception("GroupKey : Can't update loaded key.");
			for (Key k: fromGroup.keyList) keyList.add(k);
			flags |= fromGroup.GetFlags();
		}

			
		protected void ComputeBaseKey() throws Exception {
			if (!IsFullyMatched()) throw new Exception("GroupKey : Some subkeys was not defined.");
			
			if (key == null) key = new byte [descr.hashSize];
			Arrays.fill(key, (byte)0);
			
			for (Key k: keyList) {
				byte[] bk = k.GetBaseKey();
				for (int i = 0; i < descr.hashSize; i++) key[i] ^= bk[i];
			}
		}

		
		protected void CleanUp() throws Exception {
			super.CleanUp();
			for (byte[] ek: encryptedKeys) Arrays.fill(ek, (byte)0);
			cipherComp.DiscardComponent();
		}
			
		
		private void DecryptSessionKey(byte[] subkey, byte[] encKey) throws Exception {
			cipherParams.SetKey(subkey, 0, descr.hashSize);
			
			cipher.Init();
			cipher.Decrypt(encKey, 0, encryptedKeySize);
			cipher.Done();
			
			Arrays.copyOf(encKey, descr.hashSize);
		}
		
		
		private void UpdateFlags() {
			flags = 0;
			for (Key k: keyList) {
				if (k.IsMatched()) flags |= k.GetFlags();
			}
		}

		
		protected byte GetCombinedFlags() {
			byte fl = 0;
			for (Key k: keyList) fl |= k.GetFlags();
			return fl;
		}
	
		
		private IKryptelComponent cipherComp;
		private IBlockCipherParams cipherParams;
		private IBlockCipher cipher;
		
		private int encryptedKeySize;
		private ArrayList<byte[]> encryptedKeys;
	}
	
	
	//**********************************************************************
	//*** CKeyBlock
	
	
	protected ComponentDescriptor descr;
	protected SecureRandom rand;
	
	protected byte salt[] = new byte [SALT_SIZE];
	
	protected IKryptelComponent hashFuncComp;
	protected IHashFunctionParams hashFuncParams;
	protected IHashFunction hashFunc;
	
	protected Key blockKey;
	protected boolean loaded = false;
	
	
	public KeyBlock(ComponentDescriptor descr) throws Exception {
		this(descr, null);
	}
	
	
	public KeyBlock(ComponentDescriptor descr, byte[] salt) throws Exception {
		this.descr = descr;

		rand = new SecureRandom();
		rand.setSeed(rand.generateSeed(descr.hashSize));
		
		if (salt == null)
			rand.nextBytes(this.salt);
		else {
			Arrays.fill(this.salt, (byte)0);
			System.arraycopy(salt, 0, this.salt, 0, Math.min(SALT_SIZE, salt.length));
		}
		
		hashFuncComp = Loader.CreateComponent(descr.hashFunction);
		if (hashFuncComp == null) throw new Exception("Requested hash function not found.");
		hashFuncParams = (IHashFunctionParams)hashFuncComp.GetInterface(IID_IHashFunctionParams);
		hashFunc = (IHashFunction)hashFuncComp.GetInterface(IID_IHashFunction);
		
		hashFuncParams.SetHashSize(descr.hashSize);
		hashFuncParams.SetPasses(descr.hashPasses);
		hashFuncParams.SetScheme(descr.hashScheme);
	}

	
	public byte Expected() throws Exception {
		if (blockKey == null) throw new Exception("KeyBlock.Expected : Key block is empty.");
		if (!loaded) throw new Exception("KeyBlock.Expected : Invalid operation for a fully defined (not loaded) key block.");
		return blockKey.Expected();
	}
	
	
	public boolean IsMatched() throws Exception {
		if (blockKey == null) throw new Exception("KeyBlock.IsMatched : Key block is empty.");
		if (!loaded) throw new Exception("KeyBlock.IsMatched : Invalid operation for a fully defined (not loaded) key block.");
		return blockKey.IsMatched();
	}
	
	
	public byte KeyMaterial() throws Exception {
		if (blockKey == null) throw new Exception("KeyBlock.KeyMaterial : Key block is empty.");
		return blockKey.KeyMaterial();
	}


	public byte GetFlags() throws Exception {
		if (blockKey == null) throw new Exception("KeyBlock.GetFlags : Key block is empty.");
		if (blockKey.GetID() == KEY_GROUP) {
			if (!blockKey.IsLoaded()) return (byte)blockKey.GetFlags();
			
			byte fl = ((GroupKey)blockKey).GetCombinedFlags();
			// If any subkey has decryption rights, don't force it
			if ((fl & PASSWORD_CAN_DECRYPT) != 0) return blockKey.GetFlags();
		}
		
		return (byte)(blockKey.GetFlags() | PASSWORD_CAN_DECRYPT);
	}
	
	
	public byte MatchPassword(String password) throws Exception {
		if (blockKey == null) throw new Exception("KeyBlock : Can't match empty key block.");
		if (!loaded) throw new Exception("KeyBlock : Can't match fully defined (not loaded) password.");
		return blockKey.MatchPassword(password);
	}
	
	
	public byte MatchBinaryKey(byte[] binaryKey) throws Exception {
		if (blockKey == null) throw new Exception("KeyBlock : Can't match empty key block.");
		if (!loaded) throw new Exception("KeyBlock : Can't match fully defined (not loaded) binary key.");
		return blockKey.MatchBinaryKey(binaryKey);
	}


	public void AddKey(Key subkey) throws Exception {
		if (loaded) throw new Exception("KeyBlock : Can't modify loaded key block.");

		if (blockKey == null)
			blockKey = subkey;
			
		else if (blockKey.GetID() == KEY_GROUP) {				// Current key is a group
			if (subkey.GetID() == KEY_GROUP)
				((GroupKey)blockKey).AddKeysFrom((GroupKey)subkey);	// Merge groups
			else
				((GroupKey)blockKey).AddSubkey(subkey);
		}
		
		else if (subkey.GetID() == KEY_GROUP) {					// Current key is not a group, but the one being added is
			((GroupKey)subkey).AddSubkey(blockKey);
			blockKey = subkey;
		}
		
		else {																				// Create a group
			Key k = blockKey;
			blockKey = new GroupKey();
			((GroupKey)blockKey).AddSubkey(k);
			((GroupKey)blockKey).AddSubkey(subkey);
		}
	}


	public void LoadKeyBlock(byte[] keyBlockRecord) throws Exception {
		if (blockKey != null) throw new Exception("KeyBlock : Load failed - key block already defined.");
		
		System.arraycopy(keyBlockRecord, 0, salt, 0, salt.length);
		byte type = keyBlockRecord[salt.length];
		IntRef pos = new IntRef(salt.length + 1);

		switch (type) {
			case KEY_PASSWORD:
				blockKey = new Password(keyBlockRecord, pos);
				break;
				
			case KEY_BINARY_KEY:
				blockKey = new BinaryKey(keyBlockRecord, pos);
				break;
	
			case KEY_COMPOSITE:
				blockKey = new CompositeKey(keyBlockRecord, pos);
				break;
	
			case KEY_GROUP:
				blockKey = new GroupKey(keyBlockRecord, pos);
				break;
		}
		loaded = true;
	}
	
	
	public byte[] GetBaseKey() throws Exception {
		if (blockKey == null) throw new Exception("KeyBlock : Key block is not defined.");
		byte[] key = blockKey.GetBaseKey();
		return Arrays.copyOf(key, key.length);
	}


	public byte[] GetKeyBlock() throws Exception {
		if (blockKey == null) throw new Exception("KeyBlock : Can't store undefined key block.");
		SmartBuffer buffer = new SmartBuffer();
		buffer.Store(salt, 0, salt.length);
		blockKey.StoreKey(buffer);
		return buffer.Retrieve(buffer.Size());
	}
	
	
	public static byte CodeKeyLevel(int level) {
		return (byte)((level & 0x07) << 5);
	}

	
	public static int DecodeKeyLevel(byte keyID) {
		return (byte)((keyID >> 5) & 0x07);
	}
	
	
	public void CleanUp() throws Exception {
		blockKey.CleanUp();
		blockKey = null;
		loaded = false;
		Arrays.fill(salt, (byte)0);
		hashFuncComp.DiscardComponent();
	}
}
