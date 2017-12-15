/*******************************************************************************

  Product:       Kryptel/Java
  File:          ParcelLocator.java
  Description:   https://www.kryptel.com/articles/developers/java/sk.parcellocator.php

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


import java.util.UUID;


public final class ParcelLocator {
	public long parcelStart;
	public long parcelSize;					// From parcelStart to, but not including the 16-byte MD5 hash
	public UUID guidEngine;					// NULL_GUID for parcels created by Silver Key 3.x and older - not supported by Java-based extractors
	public short versionCreated;
	public short versionRequired;
}
