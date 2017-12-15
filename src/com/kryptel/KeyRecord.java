/*******************************************************************************

  Product:       Kryptel/Java
  File:          KeyRecord.java
  Description:   https://www.kryptel.com/articles/developers/java/kryptel_api.keyrecord.php

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


import static com.kryptel.Guids.NULL_GUID;

import java.util.Arrays;
import java.util.UUID;


public final class KeyRecord {
	public UUID keyMaterial;
	public String password;
	public byte[] keyData;
	public String keyPath;
	public UUID keyAssociatedMaterial;
	public byte[] keyAssociatedData;
	
	public void clear() {
		keyMaterial = NULL_GUID;
		if (keyData != null) Arrays.fill(keyData, (byte)0);
		if (keyAssociatedData != null) Arrays.fill(keyAssociatedData, (byte)0);
		keyAssociatedMaterial = NULL_GUID;
	}
}
