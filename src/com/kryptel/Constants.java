/*******************************************************************************

  Product:       Kryptel/Java
  File:          Constants.java
  Description:   https://www.kryptel.com/articles/developers/java/kryptel_api.constants.php

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


public final class Constants {
	static public final byte DEFAULT_VALUE = 0;
	static public final int DEFAULT_BUFFER_SIZE = 64 * 1024;
	static public final int HTTP_BUFFER_SIZE = 4 * 1024;
	
	static public final int BINARY_KEY_SIZE = 512;
	static public final int MAX_PASSWORD_LENGTH = (BINARY_KEY_SIZE / 2) - 1;	// UTF-16 zero-terminated string fitting in BINARY_KEY_SIZE

	static public final int VERIFICATION_LOOP_COUNT = 200;		// Default number of password verification passes

	// Component types (upper 4 bits have special meaning)

	static public final long TYPE_HASH_FUNCTION							= 0x0000000000000001L;
	static public final long TYPE_MAC												= 0x0000000000000004L;
	static public final long TYPE_BLOCK_CIPHER							= 0x0000000000000010L;
	static public final long TYPE_STREAM_CIPHER							= 0x0000000000000020L;
	static public final long TYPE_PUBLIC_KEY_CIPHER					= 0x0000000000000040L;
	static public final long TYPE_DIGITAL_SIGNATURE					= 0x0000000000000080L;
	static public final long TYPE_KEY_EXCHANGE							= 0x0000000000000100L;
	static public final long TYPE_COMPRESSOR								= 0x0000000000001000L;
	static public final long TYPE_ENCODER										= 0x0000000000008000L;
	static public final long TYPE_TRUE_RNG									= 0x0000000000010000L;
	static public final long TYPE_PSEUDO_RNG								= 0x0000000000020000L;
	static public final long TYPE_KEY_MANAGER								= 0x0000000000100000L;
	static public final long TYPE_STORAGE_HANDLER						= 0x0000000002000000L;
	static public final long TYPE_STORAGE_AGENT							= 0x0000000008000000L;
	static public final long TYPE_FILE_AGENT								= 0x0000000010000000L;
	static public final long TYPE_BACKUP_AGENT							= 0x0000000020000000L;
	static public final long TYPE_SHREDDER									= 0x0000004000000000L;
	static public final long TYPE_PARCEL_CREATOR						= 0x0000100000000000L;
	static public final long TYPE_PARCEL_EXTRACTOR					= 0x0000200000000000L;
	static public final long TYPE_WEB_STORAGE								= 0x0001000000000000L;
	static public final long TYPE_HIDDEN_COMPONENT					= 0x8000000000000000L;		// Component should not appear in user-selectable lists

	static public final long TYPE_ANY_COMPONENT							= 0x0FFFFFFFFFFFFFFFL;

	// Encrypted storage capabilities

	static public final int ESTOR_CREATE_OBJECT							= 0x00000001;
	static public final int ESTOR_DELETE_OBJECT							= 0x00000002;
	static public final int ESTOR_MODIFY_ATTRIBUTES					= 0x00000008;
	static public final int ESTOR_CREATE_STREAM							= 0x00000010;
	static public final int ESTOR_MODIFY_STREAM							= 0x00000020;
	static public final int ESTOR_EXTEND_STREAM							= 0x00000040;
	static public final int ESTOR_TRUNCATE_STREAM						= 0x00000100;
	static public final int ESTOR_DELETE_STREAM							= 0x00000200;
	static public final int ESTOR_MOVE_POINTER							= 0x00000800;
	static public final int ESTOR_MULTI_STREAM							= 0x00001000;
	static public final int ESTOR_MULTI_STREAM_READ					= 0x00002000;
	static public final int ESTOR_MULTI_STREAM_WRITE				= 0x00004000;
	static public final int ESTOR_FLUSH_SUPPORTED						= 0x00100000;
	static public final int ESTOR_CAN_BE_COMPRESSED					= 0x00200000;			// The container has unused data and can be compressed (if storage supports compression)
	static public final int ESTOR_DISCARD_CHANGES						= 0x00800000;
	static public final int ESTOR_YUBIKEY										= 0x01000000;			// Storage supports Yubikey
	static public final int ESTOR_PROTECTED_KEY							= 0x02000000;			// Storage supports protected binary keys
	static public final int ESTOR_STATISTICS								= 0x10000000;
	static public final int ESTOR_KEEPS_DELETED_OBJECTS			= 0x20000000;			// Handler does not physically removes deleted objects, just sets EFL_OBJECT_DELETED flag
	static public final int ESTOR_CAN_UNDELETE							= 0x40000000;			// If this flag is set, ESTOR_KEEPS_DELETED_OBJECTS must also be set
	static public final int ESTOR_RECOVERY_BLOCKS						= 0x80000000;

	// Agent-specific capabilities flags (high 32 bits)
	// Bits 32-47 are item-related flags, bits 48-63 are container-related flags
	static public final long EFSTOR_THUMBNAILS							= 0x0000080000000000L;
	static public final long EFSTOR_ITEM_DESCRIPTIONS				= 0x0000200000000000L;
	static public final long EFSTOR_KEYWORDS								= 0x0000400000000000L;
	static public final long EFSTOR_DESCRIPTIONS						= 0x0001000000000000L;
	static public final long EFSTOR_ENCRYPTED_DESCRIPTIONS	= 0x0002000000000000L;
	static public final long EFSTOR_ASSOCIATED_DATA					= 0x0004000000000000L;
	static public final long EFSTOR_FILE_STORAGE_STATISTICS	= 0x1000000000000000L;
	static public final long EFSTOR_TARGETS									= 0x8000000000000000L;

	// File storage control flags

	static public final int FSCF_PERSISTANT_DESCRIPTIONS		= 0x00000020;			// Inherit description if file is replaced with a newer version
	static public final int FSCF_PERSISTANT_KEYWORDS				= 0x00000040;			// Inherit keywords if file is replaced with a newer version
	static public final int FSCF_ENUMS_RETURN_DELETED				= 0x00010000;			// Enumeration functions GetDirectories and GetFiles also return deleted items
	static public final int FSCF_WILDCARDS_DECRYPT_DELETED	= 0x00020000;			// Wildcard decryption includes deleted items

	static public final int FSCF_PERSISTANT_ATTRIBUTES			= (FSCF_PERSISTANT_DESCRIPTIONS | FSCF_PERSISTANT_KEYWORDS);
	static public final int FSCF_DEFAULT										= FSCF_PERSISTANT_ATTRIBUTES;

	// Encrypted object flags

	static public final int EFL_ATTRIBUTE_BLOCK							= 0x00000001;
	static public final int EFL_DATA_STREAM									= 0x00000002;
	static public final int EFL_CHILD_OBJECTS								= 0x00000010;
	static public final int EFL_STREAM_BUSY									= 0x10000000;
	static public final int EFL_OBJECT_DELETED							= 0x80000000;


	// Encrypted file object flags (must be in higher 32 bits; lower 32 bits are reserved for system-specific attributes)

	static public final long EFFL_ITEM_IS_DIRECTORY					= 0x0000000100000000L;
	static public final long EFFL_ITEM_CONTAINS_DIRECTORIES	= 0x0000000200000000L;
	static public final long EFFL_ITEM_CONTAINS_FILES				= 0x0000000400000000L;
	static public final long EFFL_ITEM_HAS_DESCRIPTION			= 0x0000200000000000L;
	static public final long EFFL_ITEM_HAS_KEYWORDS					= 0x0000400000000000L;			// Only for files, directories can't have keywords
	static public final long EFFL_ITEM_HAS_THUMBNAILS				= 0x0010000000000000L;			// Only for files, directories can't have thumbnails
	static public final long EFFL_ITEM_DELETED							= 0x8000000000000000L;


	// Compression levels

	static public final byte CT_DEFAULT_COMPRESSION					= -1;
	static public final byte CT_NO_COMPRESSION							= 0;
	static public final byte CT_MIN_COMPRESSION							= 1;
	static public final byte CT_AVERAGE_COMPRESSION					= 6;
	static public final byte CT_MAX_COMPRESSION							= 9;

	static public final byte DEFAULT_COMPRESSION_LEVEL			= CT_AVERAGE_COMPRESSION;
}
