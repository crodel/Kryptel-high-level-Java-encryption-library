/*******************************************************************************

  Product:       Kryptel/Java
  File:          ISilverKeyStream.java
  Description:   https://www.kryptel.com/articles/developers/java/sk.isilverkeystream.php

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


public interface ISilverKeyStream {
	void CreateDirectory(String targetedPath) throws Exception;

	void StoreFile(String targetedPath, String srcPath) throws Exception;
	void StoreTree(String targetedPath, String srcPath) throws Exception;
	
	void AddMessage(String message) throws Exception;
}
