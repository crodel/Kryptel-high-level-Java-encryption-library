/*******************************************************************************

  Product:       Kryptel/Java
  File:          Capabilities.java
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


public final class Capabilities {
	static public final long CAP_NO_CAPABILITIES									= 0x0000000000000000L;
	static public final long CAP_DEFAULT_CAPABILITIES							= 0xFFFFFFFFFFFFFFFFL;
	static public final long CAP_INVALID_CAPABILITIES_MASK				= 0xFFFFFFFFFFFFFFFFL;

	// Generic capabilities
	static public final long CAP_64_BIT_PROCESSING								= 0x0000000000000001L;
	static public final long CAP_MULTI_THREAD_PROCESSING					= 0x0000000000000002L;
	// Key manager capabilities
	static public final long CAP_ADVANCED_PASSWORD_DIALOG					= 0x0000000000000100L;
	static public final long CAP_BINARY_KEYS											= 0x0000000000000200L;
	// Encrypted storage
	static public final long CAP_THUMBNAIL_PRERENDERING						= 0x0000000000010000L;
	static public final long CAP_RECOVERY_BLOCKS									= 0x0000000000020000L;
	// Encrypted storage and Silver Key engine
	static public final long CAP_YUBIKEY													= 0x0000000000100000L;
	static public final long CAP_FIPS_140_2												= 0x0000000000800000L;
	// Shredder
	static public final long CAP_MULTI_PASS_SHREDDING							= 0x0000000010000000L;
	static public final long CAP_SHREDDER_UI											= 0x0000000020000000L;
	// Features
	static public final long CAP_COMMAND_LINE											= 0x0000001000000000L;
	// Silver Key features
	static public final long CAP_SHELL														= 0x0000100000000000L;
	static public final long CAP_JOBS															= 0x0000200000000000L;
	static public final long CAP_SMALL_PARCEL_OBFUSCATION					= 0x0000400000000000L;
	static public final long CAP_HIDDEN_PARCELS										= 0x0000800000000000L;
	static public final long CAP_UNCOMPRESSED_STUBS								= 0x0001000000000000L;
	static public final long CAP_COMPATIBILITY_ENGINE							= 0x0002000000000000L;
	static public final long CAP_WEB_STORAGE											= 0x0004000000000000L;
	static public final long CAP_DIGITAL_SIGNATURES								= 0x0008000000000000L;
	// Kryptel features
	static public final long CAP_BROWSER													= 0x0010000000000000L;
	static public final long CAP_DATASETS													= 0x0040000000000000L;
}
