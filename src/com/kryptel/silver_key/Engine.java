/*******************************************************************************

  Product:       Kryptel/Java
  File:          Engine.java
  Description:   https://www.kryptel.com/articles/developers/java/sk.php

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


import static com.kryptel.Capabilities.CAP_DEFAULT_CAPABILITIES;
import static com.kryptel.Constants.TYPE_PARCEL_CREATOR;
import static com.kryptel.Constants.TYPE_PARCEL_EXTRACTOR;
import static com.kryptel.Guids.CID_SILVER_KEY;
import static com.kryptel.Guids.IID_IComponentCapabilities;
import static com.kryptel.Guids.IID_IComponentState;
import static com.kryptel.Guids.IID_IKryptelComponent;
import static com.kryptel.Guids.IID_ISilverKeyExtractor;
import static com.kryptel.Guids.IID_ISilverKeyParcel;

import java.util.UUID;

import com.kryptel.IComponentCapabilities;
import com.kryptel.IComponentState;
import com.kryptel.IKryptelComponent;


final class Engine implements IKryptelComponent,
															IComponentCapabilities,
															IComponentState,
															AutoCloseable {

	static final short ENGINE_VERSION = (short)0x0700;
	static final short MINIMAL_COMPATIBLE_ENGINE_VERSION = (short)0x0600;
	static final short ENGINE_VERSION_WITH_CORRECT_HMAC = (short)0x0700;

	Engine(long capabilities) throws Exception {
		compCapabilities = capabilities;
		parcelCreator = new Parcel(capabilities);
		parcelExtractor = new Extractor(capabilities);
	}
	
	
	//
	// IKryptelComponent
	//
	
	public long ComponentType() { return componentType; }
	public UUID ComponentID() { return componentID; }
	public String ComponentName() { return "Silver Key Engine"; }
	
	public Object GetInterface(UUID iid) {
		if (iid.equals(IID_IKryptelComponent) || iid.equals(IID_IComponentCapabilities) || iid.equals(IID_IComponentState)) return this;

		if (iid.equals(IID_ISilverKeyParcel)) return parcelCreator;

		if (iid.equals(IID_ISilverKeyExtractor)) return parcelExtractor;

		return null;
	}
	
	public void DiscardComponent() throws Exception { Reset(); }
	
	
	//
	// IComponentCapabilities
	//

	public long GetCapabilitiesMask() { return compCapabilities; }
	
	public void SetCapabilitiesMask(long capabilities) {
		compCapabilities = capabilities;
		parcelCreator.SetCapabilities(capabilities);
		parcelExtractor.SetCapabilities(capabilities);
	}
	
	
	//
	// IComponentState
	//

	public ComponentState GetState() { return parcelCreator.IsOpen() ? ComponentState.ComponentBusy : ComponentState.ComponentIdle; }

	public void Reset() throws Exception { parcelCreator.Reset(); parcelExtractor.Reset(); }

	public IKryptelComponent Clone() throws Exception {
		return new Engine(compCapabilities);
	}
	
	
	//
	// AutoCloseable
	//

	public void close() throws Exception { DiscardComponent(); }
	
	
  //
  // Private data and methods
  //

  static long componentType = TYPE_PARCEL_CREATOR | TYPE_PARCEL_EXTRACTOR;
  static UUID componentID = CID_SILVER_KEY;

	private long compCapabilities = CAP_DEFAULT_CAPABILITIES;
	
	private Parcel parcelCreator;
	private Extractor parcelExtractor;
}
