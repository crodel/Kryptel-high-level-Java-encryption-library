/*******************************************************************************

  Product:       Kryptel/Java
  File:          KeyIdent.java
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


public final class KeyIdent {
	static public final UUID IDENT_NULL												= UUID.fromString("00000000-0000-0000-0000-000000000000");
	static public final UUID IDENT_INVALID_KEY								= UUID.fromString("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF");
	static public final UUID IDENT_RAW_BINARY_KEY							= UUID.fromString("0001AFEF-0000-0000-0000-000000000000");	// User-defined raw binary key
	static public final UUID IDENT_FILE_BASED_KEY							= UUID.fromString("00110562-0000-0000-0000-000000000000");
	static public final UUID IDENT_PROTECTED_KEY							= UUID.fromString("00620511-0000-0000-0000-000000000000");	// Key + password
	static public final UUID IDENT_PUBLIC_KEY									= UUID.fromString("02009172-0000-0000-0000-000000000000");
	static public final UUID IDENT_PASSWORD										= UUID.fromString("000031F1-0000-0000-0000-000000000000");
	static public final UUID IDENT_LOWERCASE_PASSWORD					= UUID.fromString("0001AE7B-0000-0000-0000-000000000000");
	static public final UUID IDENT_YUBIKEY										= UUID.fromString("0002AE05-0000-0000-0000-000000000000");
	static public final UUID IDENT_YUBIKEY_PASSWORD						= UUID.fromString("0002AE15-0000-0000-0000-000000000000");
}
