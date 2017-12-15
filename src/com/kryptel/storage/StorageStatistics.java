/*******************************************************************************

  Product:       Kryptel/Java
  File:          StorageStatistics.java
  Description:   https://www.kryptel.com/articles/developers/java/storage.storagestatistics.php

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


package com.kryptel.storage;


public class StorageStatistics {
	public long uBaseSegmentSize;
	
	public int uAgentDataSize;
	public long uBaseDataAreaSize;					// Total data area size is uBaseDataAreaSize + uTotalFixupDataAreaSize
	public long uDirectorySize;
	
	public int nFixupSegments;
	public long uTotalFixupSegmentSize;

	public long uTotalFixupDataAreaSize;		// Total data area size is uBaseDataAreaSize + uTotalFixupDataAreaSize
	public long uTotalFixupListSize;
	public int nFixupRecords;
	
	public int nObjects;										// Total number of
	public int nDeletedObjects;							//   objects is nObjects + nDeletedObjects
	public int nAttributeBlocks;
	public long uTotalAttributeSize;
	public int nStreams;
	public long uDataAreaUsed;
	public long uDataAreaUnused;						// For unmodified container equals to (uBaseDataAreaSize + uTotalFixupDataAreaSize) - (uDataAreaUsed + uTotalRecoveryBlockSize)
	public long uTotalStreamSize;						// Of uncompressed data
	
	public int nRecoveryBlocks;
	public long uTotalRecoveryBlockSize;
}
