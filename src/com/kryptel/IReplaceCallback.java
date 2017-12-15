/*******************************************************************************

  Product:       Kryptel/Java
  File:          IReplaceCallback.java
  Description:   https://www.kryptel.com/articles/developers/java/kryptel_api.ireplacecallback.php

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


//
// oldFilePath contains the full path
// newFileName is an output-only argument. If the callback returns REPLACE_ACTION.RENAME, newFileName must contain a new file name
//


public interface IReplaceCallback {
	enum REPLACE_ACTION { REPLACE, SKIP, RENAME, VERSION, ABORT };
	static final REPLACE_ACTION DEFAULT_REPLACE_ACTION = REPLACE_ACTION.REPLACE;
	
	REPLACE_ACTION Callback(Object arg, StringBuilder newFileName, long newSize, long newDate, String oldFilePath, long oldSize, long oldDate) throws Exception;
}
