/*******************************************************************************

  Product:       Kryptel/Java
  File:          ComponentLoader.java
  Description:   https://www.kryptel.com/articles/developers/java/intro.components.php

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


package com.kryptel.hash_function;


import static com.kryptel.Guids.CID_HASH_MD5;
import static com.kryptel.Guids.CID_HASH_SHA1;
import static com.kryptel.Guids.CID_HASH_SHA256;
import static com.kryptel.Guids.CID_HASH_SHA384;
import static com.kryptel.Guids.CID_HASH_SHA512;
import static com.kryptel.Guids.CID_HASH_SHA512_64;
import static com.kryptel.Guids.CID_NULL_HASH_FUNCTION;

import java.util.List;
import java.util.UUID;

import com.kryptel.IKryptelComponent;


public final class ComponentLoader {
	public static IKryptelComponent CreateComponent(UUID cid, long capabilities) throws Exception {
		if (cid.equals(CID_HASH_MD5)) return new Md5(capabilities);
		if (cid.equals(CID_HASH_SHA1)) return new Sha1(capabilities);
		if (cid.equals(CID_HASH_SHA256)) return new Sha256(capabilities);
		if (cid.equals(CID_HASH_SHA384)) return new Sha384(capabilities);
		if (cid.equals(CID_HASH_SHA512)) return new Sha512(capabilities, false);
		if (cid.equals(CID_HASH_SHA512_64)) return new Sha512(capabilities, true);

		if (cid.equals(CID_NULL_HASH_FUNCTION)) return new NullHashFunction(capabilities);
		
		return null;
	}
	
	
	public static void GetComponentList(List<UUID> uidList, long mask) {
		if ((Md5.componentType & mask) != 0) uidList.add(Md5.componentID);
		if ((Sha1.componentType & mask) != 0) uidList.add(Sha1.componentID);
		if ((Sha256.componentType & mask) != 0) uidList.add(Sha256.componentID);
		if ((Sha384.componentType & mask) != 0) uidList.add(Sha384.componentID);
		if ((Sha512.componentType & mask) != 0) uidList.add(Sha512.componentID);
		if ((NullHashFunction.componentType & mask) != 0) uidList.add(NullHashFunction.componentID);
	}
}
