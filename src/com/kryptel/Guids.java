/*******************************************************************************

  Product:       Kryptel/Java
  File:          Guids.java
  Description:   https://www.kryptel.com/articles/developers/java/kryptel_api.php

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


package com.kryptel;


import java.util.UUID;


//
// IMPORTANT! Component IDs "11056249-400A-4461-BD5E-xxxxxxxxxxxx" are reserved.
// If you add a component, choose a different prefix.
//


public final class Guids {
	static public final UUID NULL_GUID												= UUID.fromString("00000000-0000-0000-0000-000000000000");
	
	// NULL low-level components

	static public final UUID CID_NULL_CIPHER									= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1000");
	static public final UUID CID_NULL_COMPRESSOR							= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1010");
	static public final UUID CID_NULL_HASH_FUNCTION						= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1020");

	// Ciphers

	static public final UUID CID_CIPHER_AES										= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1001");
	static public final UUID CID_CIPHER_BLOWFISH							= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1002");
	static public final UUID CID_CIPHER_DES										= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1003");
	static public final UUID CID_CIPHER_TRIPLE_DES						= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1004");
	static public final UUID CID_CIPHER_SERPENT								= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1006");
	static public final UUID CID_CIPHER_TWOFISH								= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1007");

	// Compressors

	static public final UUID CID_COMPRESSOR_ZIP								= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1012");
	
	// Hash functions

	static public final UUID CID_HASH_MD5											= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1022");
	static public final UUID CID_HASH_SHA1										= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1025");
	static public final UUID CID_HASH_SHA256									= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1026");
	static public final UUID CID_HASH_SHA384									= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1027");
	static public final UUID CID_HASH_SHA512									= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1128");

	// This component incorrectly returns block size 64, thus producing incorrect HMACs. The hash result itself is correct.
	// Used for compatibility with older versions.
	static public final UUID CID_HASH_SHA512_64								= UUID.fromString("11056249-400A-4461-BD5E-FE06113A1028");

	static public final UUID CID_HMAC													= UUID.fromString("11056249-400A-4461-BD5E-FE06113A10C1");
	static public final UUID CID_CMAC													= UUID.fromString("11056249-400A-4461-BD5E-FE06113A10C2");

	// Encrypted storage

	static public final UUID CID_BASIC_STORAGE								= UUID.fromString("11056249-400A-4461-BD5E-FE06113BA006");
	static public final UUID CID_FIPS140_STORAGE							= UUID.fromString("11056249-400A-4461-BD5E-FE06113BA0B6");
	
	static public final UUID CID_STORAGE_7										= UUID.fromString("11056249-400A-4461-BD5E-FE06113BA007");
	static public final UUID CID_FIPS140_STORAGE_7						= UUID.fromString("11056249-400A-4461-BD5E-FE06113BA0B7");
	
	static public final UUID CID_FILE_AGENT										= UUID.fromString("11056249-400A-4461-BD5E-FE06113BC006");
	static public final UUID CID_BACKUP_AGENT									= UUID.fromString("11056249-400A-4461-BD5E-FE06113BC016");
	
	static public final UUID CID_YUBIKEY_STORAGE							= UUID.fromString("11056249-400A-4461-BD5E-FE06113BF001");	// A non-component CID. This CID in the agent field indicates Yubikey storage.

	// Silver Key Encryption Engine

	static public final UUID CID_SILVER_KEY_3									= UUID.fromString("11056249-400A-4461-BD5E-FE06113CA000");
	static public final UUID CID_SILVER_KEY										= UUID.fromString("11056249-400A-4461-BD5E-FE06113CA001");
	static public final UUID CID_SILVER_KEY_FIPS							= UUID.fromString("11056249-400A-4461-BD5E-FE06113CA008");

	static public final UUID CID_PARCEL_GUID									= UUID.fromString("11056249-400A-4461-BD5E-BC88BE020401");	// A non-component CID. See note on 'Parcel GUID' in parcel format specs

	// Web storage handlers

	static public final UUID CID_DROPBOX											= UUID.fromString("11056249-400A-4461-BD5E-FE06113AC001");
	static public final UUID CID_GOOGLE_DRIVE									= UUID.fromString("11056249-400A-4461-BD5E-FE06113AC005");
	static public final UUID CID_ONEDRIVE											= UUID.fromString("11056249-400A-4461-BD5E-FE06113AC009");

	
	//
	// Interfaces
	//

	static public final UUID IID_IKryptelComponent							= UUID.fromString("0F14695E-EF3E-4E3B-8A83-F665E039EA87");
	static public final UUID IID_IComponentCapabilities					= UUID.fromString("2D9EEB96-AEDE-4E40-9E89-7335C736EE58");
	static public final UUID IID_IComponentState								= UUID.fromString("8F81FAFD-5C3A-440D-AE43-2294192A97C8");
	static public final UUID IID_IPreferencesHandler						= UUID.fromString("37E04B3C-1BD0-4d6a-8380-11C0ACAEDD77");

	static public final UUID IID_ICipherParams									= UUID.fromString("E0AEB404-E1F6-4F89-B09D-310F709E0D01");
	static public final UUID IID_IBlockCipherParams							= UUID.fromString("CE5432FE-C10B-4E1C-95A3-F6284756D385");
	static public final UUID IID_IRawBlockCipher								= UUID.fromString("3DA8B7A7-02DF-4360-8AF8-E9F9E35DB9B1");
	static public final UUID IID_IBlockCipher										= UUID.fromString("C0AFD8C1-4104-42D9-8BF5-2EC0A92BA841");
	static public final UUID IID_ICipher												= UUID.fromString("EA26AD5C-C4CD-4F26-AD01-E803B43E0B8B");

	static public final UUID IID_ICompressorParams							= UUID.fromString("CB09B15C-A484-413E-9D57-B3224BE229B6");
	static public final UUID IID_IMemoryBlockCompressor					= UUID.fromString("7853B7FB-2BB3-4272-98E2-E2947D2E6BCE");
	static public final UUID IID_ICompressor										= UUID.fromString("84E4C9A4-E1B8-4A63-8B71-C0D516F9B60D");

	static public final UUID IID_IHashFunctionParams						= UUID.fromString("B0D928BC-73D4-4E50-B542-4E77701A5A89");
	static public final UUID IID_IHashFunction									= UUID.fromString("9BB7469B-EE4B-47EE-A1EE-77096598CD6B");
	static public final UUID IID_IMemoryBlockHash								= UUID.fromString("5BD59EBB-CB6C-4853-8161-EAC195226D1A");

	static public final UUID IID_IMacSetup											= UUID.fromString("21100772-B18B-4B4D-979F-4BAD8B6C8C26");

	static public final UUID IID_IEncryptedStorage							= UUID.fromString("7F21394E-DD70-4024-BC4E-01DDD17137FC");
	static public final UUID IID_IEncryptedStorageInquirer			= UUID.fromString("B3871B47-4E6C-458b-A080-E0A603C27E0A");

	static public final UUID IID_IEncryptedFileStorage					= UUID.fromString("0C24FD55-ACF7-4eb3-8E78-D99848B560D4");
	static public final UUID IID_IEncryptedFileStorageInquirer	= UUID.fromString("EBD681C5-0D02-46ae-AB0B-1AFA89ABDAFE");

	static public final UUID IID_ISilverKeyParcel								= UUID.fromString("830D8DC3-05E7-4173-BC7A-E894B895E2F0");
	static public final UUID IID_ISilverKeyExtractor						= UUID.fromString("830D8DC3-05E7-4173-BC7A-E894B895E20F");

	static public final UUID IID_IWebStorage										= UUID.fromString("92FBCC3F-B974-4F25-938D-1ACEB7131DE0");
	static public final UUID IID_IWebStorageAuthorizer					= UUID.fromString("92FBCC3F-B974-4F25-938D-1ACEB7131DE1");

}
