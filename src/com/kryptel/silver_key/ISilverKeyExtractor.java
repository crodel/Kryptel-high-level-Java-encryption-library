/*******************************************************************************

  Product:       Kryptel/Java
  File:          ISilverKeyExtractor.java
  Description:   https://www.kryptel.com/articles/developers/java/sk.isilverkeyextractor.php

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


import com.kryptel.IKeyCallback;
import com.kryptel.INotification;
import com.kryptel.IProgressCallback;
import com.kryptel.IReplaceCallback;


public interface ISilverKeyExtractor {
	interface IMessage {
		boolean Show(String parcelTitle, String message);		// Returns false if user requested abort
	}
	
	class ParcelStatistics {
		// Parcel statistics
		public int nDirs, nFiles;		// Value -1 means
		public long totalBytes;			//   unknown (if no COMMAND_PROGRESS)
		// Data extracted
		public int nDirsCreated, nFilesCreated;
		public long bytesWritten;
	}
	
	void ExtractData(String targetDir, String parcelPath, Object arg,
									IKeyCallback keyFunc,
									IProgressCallback progressFunc,
									IReplaceCallback replaceCallback,
									IMessage msgCallback,
									INotification notificationCallback) throws Exception;
	
	ParcelStatistics GetExtractionStatistics() throws Exception;
}
