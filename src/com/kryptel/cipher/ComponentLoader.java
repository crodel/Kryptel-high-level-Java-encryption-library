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


package com.kryptel.cipher;


import static com.kryptel.Guids.CID_CIPHER_AES;
import static com.kryptel.Guids.CID_CIPHER_BLOWFISH;
import static com.kryptel.Guids.CID_CIPHER_DES;
import static com.kryptel.Guids.CID_CIPHER_SERPENT;
import static com.kryptel.Guids.CID_CIPHER_TRIPLE_DES;
import static com.kryptel.Guids.CID_CIPHER_TWOFISH;
import static com.kryptel.Guids.CID_NULL_CIPHER;

import java.util.List;
import java.util.UUID;

import com.kryptel.IKryptelComponent;


public final class ComponentLoader {
	public static IKryptelComponent CreateComponent(UUID cid, long capabilities) {
		if (cid.equals(CID_CIPHER_AES)) return new Aes(capabilities);
		if (cid.equals(CID_CIPHER_BLOWFISH)) return new Blowfish(capabilities);
		if (cid.equals(CID_CIPHER_DES)) return new Des(capabilities);
		if (cid.equals(CID_CIPHER_TRIPLE_DES)) return new TripleDes(capabilities);
		if (cid.equals(CID_CIPHER_SERPENT)) return new Serpent(capabilities);
		if (cid.equals(CID_CIPHER_TWOFISH)) return new Twofish(capabilities);

		if (cid.equals(CID_NULL_CIPHER)) return new NullCipher(capabilities);

		return null;
	}
	
	
	public static void GetComponentList(List<UUID> uidList, long mask) {
		if ((Aes.componentType & mask) != 0) uidList.add(Aes.componentID);
		if ((Blowfish.componentType & mask) != 0) uidList.add(Blowfish.componentID);
		if ((Des.componentType & mask) != 0) uidList.add(Des.componentID);
		if ((TripleDes.componentType & mask) != 0) uidList.add(TripleDes.componentID);
		if ((Serpent.componentType & mask) != 0) uidList.add(Serpent.componentID);
		if ((Twofish.componentType & mask) != 0) uidList.add(Twofish.componentID);
		if ((NullCipher.componentType & mask) != 0) uidList.add(NullCipher.componentID);
	}
}
