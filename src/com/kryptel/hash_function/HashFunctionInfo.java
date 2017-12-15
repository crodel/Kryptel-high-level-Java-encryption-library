/*******************************************************************************

  Product:       Kryptel/Java
  File:          HashFunctionInfo.java
  Description:   https://www.kryptel.com/articles/developers/java/hash.hashfunctioninfo.php

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


final public class HashFunctionInfo {
	final public int ValidHashSizes[];
	final public int ValidPasses[];
	final public String Schemes[];
	
	HashFunctionInfo(int[] HashSizeList, int[] PassesList, String[] sch) {
		ValidHashSizes = HashSizeList;
		ValidPasses = PassesList;
		Schemes = sch;
	}

	public String toString() {
		String strHashSizes = new String();
		for (int h: ValidHashSizes) {
			if (strHashSizes.length() > 0) strHashSizes += ", ";
			strHashSizes += h;
		}
		
		String strPasses = new String();
		for (int p: ValidPasses) {
			if (strPasses.length() > 0) strPasses += ", ";
			strPasses += p;
		}
		
		String strSchemes = new String();
		for (String s: Schemes) {
			if (strSchemes.length() > 0) strSchemes += ", ";
			strSchemes += "\"" + s + "\"";
		}
		
		return "{ ValidHashSizes: { " + strHashSizes + " }, ValidPasses: { " + strPasses + " }, Schemes: { " + strSchemes + " } }";
	}
}
