/*******************************************************************************

  Product:       Kryptel/Java
  File:          DefaultPreferencesHandler.java
  Description:   This handler is used when the implementation does not provide
                 a more specific one.

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


import java.util.prefs.Preferences;


public class DefaultPreferencesHandler implements IPreferencesHandler.IPreferences {
	
	public DefaultPreferencesHandler(String root) {
		prefs = Preferences.userRoot().node(root);
	}
	
	// IPreferencesHandler.IPreferences
	
	public void SetInteger(String key, int val) throws Exception {
		prefs.putInt(key, val);
	}
	
	public void SetString(String key, String str) throws Exception {
		prefs.put(key, str);
	}
	
	public int GetInteger(String key, int defaultVal) throws Exception {
		return prefs.getInt(key, defaultVal);
	}
	
	public String GetString(String key, String defaultStr) throws Exception {
		return prefs.get(key, defaultStr);
	}

	public void Remove(String key) throws Exception {
		prefs.remove(key);
	}
	
	public void Flush() throws Exception {
		prefs.flush();
	}
	
	//
	// Private data
	//
	
	private final Preferences prefs;
}
