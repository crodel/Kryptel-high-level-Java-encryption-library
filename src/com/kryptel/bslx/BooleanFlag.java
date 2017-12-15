/*******************************************************************************

  Product:       Kryptel/Java
  File:          BooleanFlag.java
  Description:   https://www.kryptel.com/articles/developers/java/bslx.booleanflag.php

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


package com.kryptel.bslx;

public final class BooleanFlag {
	private boolean flag;
	
	public BooleanFlag() { flag = false; }
	public BooleanFlag(boolean fl) { flag = fl; }
	
	public boolean is_set() { return flag; }
	public boolean get() { return flag; }
	public void set(boolean fl) { flag = fl; }
}
