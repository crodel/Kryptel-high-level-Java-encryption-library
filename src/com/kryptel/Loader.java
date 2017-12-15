/*******************************************************************************

  Product:       Kryptel/Java
  File:          Loader.java
  Description:   https://www.kryptel.com/articles/developers/java/kryptel_api.loader.php

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


import static com.kryptel.Capabilities.CAP_DEFAULT_CAPABILITIES;

import java.util.ArrayList;
import java.util.UUID;


public class Loader {
	public static IKryptelComponent CreateComponent(UUID cid) throws Exception { return CreateComponent(cid, CAP_DEFAULT_CAPABILITIES); }
	
	public static IKryptelComponent CreateComponent(UUID cid, long capabilities) throws Exception {
		IKryptelComponent comp;
		
		comp = com.kryptel.cipher.ComponentLoader.CreateComponent(cid, capabilities);
		if (comp != null) return comp;
		
		comp = com.kryptel.compressor.ComponentLoader.CreateComponent(cid, capabilities);
		if (comp != null) return comp;
		
		comp = com.kryptel.hash_function.ComponentLoader.CreateComponent(cid, capabilities);
		if (comp != null) return comp;
		
		comp = com.kryptel.mac.ComponentLoader.CreateComponent(cid, capabilities);
		if (comp != null) return comp;
		
		comp = com.kryptel.silver_key.ComponentLoader.CreateComponent(cid, capabilities);
		if (comp != null) return comp;
		
		comp = com.kryptel.storage.ComponentLoader.CreateComponent(cid, capabilities);
		if (comp != null) return comp;
		
		return null;
	}


	public static UUID[] GetComponentList(long mask) {
		ArrayList<UUID> uidList = new ArrayList<UUID>();

		com.kryptel.cipher.ComponentLoader.GetComponentList(uidList, mask);
		com.kryptel.compressor.ComponentLoader.GetComponentList(uidList, mask);
		com.kryptel.hash_function.ComponentLoader.GetComponentList(uidList, mask);
		com.kryptel.mac.ComponentLoader.GetComponentList(uidList, mask);
		com.kryptel.silver_key.ComponentLoader.GetComponentList(uidList, mask);
		com.kryptel.storage.ComponentLoader.GetComponentList(uidList, mask);
		
		return (UUID[])uidList.toArray(new UUID[uidList.size()]);
	}
}
