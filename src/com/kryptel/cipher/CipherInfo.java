/*******************************************************************************

  Product:       Kryptel/Java
  File:          CipherInfo.java
  Description:   https://www.kryptel.com/articles/developers/java/cipher.cipherinfo.php

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

final public class CipherInfo {
	final public int ValidKeySizes[];
	final public int ValidBlockSizes[];
	final public int ValidRounds[];
	final public String Schemes[];
	
	CipherInfo(int[] KeySizeList, int[] BlockSizeList, int[] RoundsList, String[] sch) {
		ValidKeySizes = KeySizeList;
		ValidBlockSizes = BlockSizeList;
		ValidRounds = RoundsList;
		Schemes = sch;
	}

	public String toString() {
		String strKeySizes = new String();
		for (int k: ValidKeySizes) {
			if (strKeySizes.length() > 0) strKeySizes += ", ";
			strKeySizes += k;
		}
		
		String strBlockSizes = new String();
		for (int b: ValidBlockSizes) {
			if (strBlockSizes.length() > 0) strBlockSizes += ", ";
			strBlockSizes += b;
		}
		
		String strRounds = new String();
		for (int r: ValidRounds) {
			if (strRounds.length() > 0) strRounds += ", ";
			strRounds += r;
		}
		
		String strSchemes = new String();
		for (String s: Schemes) {
			if (strSchemes.length() > 0) strSchemes += ", ";
			strSchemes += "\"" + s + "\"";
		}
		
		return "{ ValidKeySizes: { " + strKeySizes + " }, ValidBlockSizes: { " + strBlockSizes + " }, ValidRounds: { " + strRounds + " }, Schemes: { " + strSchemes + " } }";
	}
}
