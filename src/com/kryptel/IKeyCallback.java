/*******************************************************************************

  Product:       Kryptel/Java
  File:          IKeyCallback.java
  Description:   https://www.kryptel.com/articles/developers/java/kryptel_api.ikeycallback.php

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


public interface IKeyCallback {
	// Allowed key material
	static final int USER_DEFINED_KEY						= 0x00000001;	// User-defined raw binary key
	static final int FILE_BASED_KEY							= 0x00000002;
	static final int BINARY_KEY									= 0x00000010;	// Key file
	static final int PROTECTED_KEY							= 0x00000020;	// Key file + password
	static final int PUBLIC_KEY									= 0x00001000;
	static final int PASSWORD										= 0x00040000;
	static final int LOWERCASE_PASSWORD					= 0x00080000;
	static final int YUBIKEY										= 0x02000000;
	static final int YUBIKEY_PASSWORD						= 0x04000000;

	static final int PASSWORDS									= PASSWORD | LOWERCASE_PASSWORD;
	static final int KEY_FILES									= BINARY_KEY | PROTECTED_KEY;
	static final int YUBIKEYS										= YUBIKEY | YUBIKEY_PASSWORD;
	static final int ANY_KEY_MATERIAL						= USER_DEFINED_KEY | FILE_BASED_KEY | KEY_FILES | PUBLIC_KEY | PASSWORDS | YUBIKEYS;
	
	//
	// arg is user-defined argument, for example arg in ISilverKeyParcel.Create
	// prompt usually contains the name of the file to be encrypted/decrypted
	// allowed is a mask of allowed key material (see above constants)
	// expected is the key file that we are expecting, should be ignored if allowed != BINARY_KEY. May be null.
	//          if allowed == BINARY_KEY and expected == null, any key file will do.
	//
	
	KeyRecord Callback(Object arg, String prompt, int allowed, UUID expected) throws Exception;		// Returns null if user requested abort
}
