/*******************************************************************************

  Product:       Kryptel/Java
  File:          ISilverKeyParcel.java
  Description:   https://www.kryptel.com/articles/developers/java/sk.isilverkeyparcel.php

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


import com.kryptel.IDataSink;
import com.kryptel.IKeyCallback;
import com.kryptel.IKryptelComponent;
import com.kryptel.IProgressCallback;


public interface ISilverKeyParcel {
	enum PARCEL_TYPE { STUB, STUBLESS, APPEND };
	
	void SetParcelTitle(String title) throws Exception;
	void AttachDescription(String description) throws Exception;

	ISilverKeyStream Create(String fileName, PARCEL_TYPE type, IKryptelComponent cipher, Object arg, IKeyCallback keyFunc, IProgressCallback progressFunc) throws Exception;
	ISilverKeyStream Create(IDataSink sink, Object sinkArg, String fileName, PARCEL_TYPE type, IKryptelComponent cipher, Object arg, IKeyCallback keyFunc, IProgressCallback progressFunc) throws Exception;

	void Close() throws Exception;
}
