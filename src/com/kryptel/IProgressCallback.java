/*******************************************************************************

  Product:       Kryptel/Java
  File:          IProgressCallback.java
  Description:   https://www.kryptel.com/articles/developers/java/kryptel_api.iprogresscallback.php

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


public interface IProgressCallback {
	static final int PROGRESS_STEPS = 100;
	static final int MIN_SIZE_TO_STEP = (16 * 1024);
	static final int NO_TOTAL_PROGRESS_BAR = -1;
	
	boolean Callback(Object arg, String curFile, int stepFile, int stepTotal) throws Exception;
}
