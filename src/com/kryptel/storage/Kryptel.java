/*******************************************************************************

  Product:       Kryptel/Java
  File:          Kryptel.java
  Description:   https://www.kryptel.com/articles/developers/java/storage.kryptel.php

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


import static com.kryptel.bslx.Conversions.*;

import java.io.File;
import java.io.FileInputStream;
import java.util.UUID;


public final class Kryptel {
	public static final int CONTAINER_TAG											= 0x07AA050B;
	public static final int TRAILER_TAG												= 0x0B0507AA;

	public static final int FIXUP_IN_PROGRESS_TAG							= 0x70ADB050;
	public static final int FIXUP_TAG													= 0x70AEB050;
	public static final int FIXUP_TRAILER_TAG									= 0x0B0507AB;

	public static final int RECOVERY_BLOCK_TAG								= 0xE0EAF0C8;

	public static final int ALIGNMENT_BOUNDARY								= 4096;		// Must be power of 2

	public static final int CONTAINER_TRAILER_SIZE						= 98;			// (sizeof(DWORD) + sizeof(WORD) + 2 * 6 + 5 * sizeof(MD5::MD5_HASH))
	public static final int FIXUP_SEGMENT_TRAILER_SIZE				= 102;		// (sizeof(DWORD) + 3 * 6 + 5 * sizeof(MD5::MD5_HASH))

	public static final short OBJECT_START										= 0x050B;
	public static final short OBJECT_END											= 0x07AA;

	public static final int NO_AGENT_DATA											= 0;
	public static final int REMOVE_AGENT_DATA									= -1;

	public static final short FIXUP_RECORD_CREATE_OBJECT			= (short)0xAE50;
	public static final short FIXUP_RECORD_ATTACH_ATTRIBUTES	= (short)0xAE54;
	public static final short FIXUP_RECORD_ATTACH_DATA				= (short)0xAE55;
	public static final short FIXUP_RECORD_ADD_OBJECT					= (short)0xAE59;
	public static final short FIXUP_RECORD_MOVE_OBJECT				= (short)0xAE5D;
	public static final short FIXUP_RECORD_DELETE_OBJECT			= (short)0xAE5E;
	public static final short FIXUP_RECORD_UNDELETE_OBJECT		= (short)0xAE5F;


	// IDs of agent's objects
	
	public static final int ID_TARGET													= 0x3E050B22;
	public static final int ID_DIRECTORY											= 0x3E050B25;
	public static final int ID_FILE														= 0x3E050B2B;
	public static final int ID_STREAM													= 0x3E050BCB;
	public static final int ID_THUMBNAILS											= 0x3E050BEB;

	
	// System codes for system-specific attributes
	
	public static final byte SYSTEM_NEUTRAL          					= 0;
	public static final byte SYSTEM_WINDOWS          					= 1;
	public static final byte SYSTEM_WINDOWS_MOBILE   					= 5;
	public static final byte SYSTEM_LINUX            					= 10;
	public static final byte SYSTEM_MAC              					= 20;

	
	public static final String UNIQUE_FILE_NAME_PREFIX				= ":>>";			// Prefix made of invalid filename chars to avoid name conflict (however it must not include wildcard characters)
	
	public static final String FILE_DELETED_SUFFIX						= " {deleted}";
	
	
	public static final class ContainerHandlers {
		public final int tag;
		public final UUID agent;
		public final UUID storage;
		
		ContainerHandlers(int tag, UUID agent, UUID storage) { this.tag = tag; this.agent = agent; this.storage = storage; }
	}
	
	
	//
	// Helper functions
	//
	
	
	public static boolean IsContainer(String path) {
		File f = new File(path);
		if (!f.isFile() || !f.canRead()) return false;
		if (f.length() < 42) return false;
		
		try (FileInputStream fin = new FileInputStream(f)) {
			byte[] buf = new byte [4];
			fin.read(buf);
			return GetAsInt(buf, 0) == CONTAINER_TAG;
		}
		catch (Exception e) {
			return false;
		}
	}
	
	
	public static ContainerHandlers GetContainerHandlers(String path) {
		File f = new File(path);
		if (!f.isFile() || !f.canRead()) return null;
		if (f.length() < 42) return null;
		
		try (FileInputStream fin = new FileInputStream(f)) {
			byte[] buf = new byte [16];
			fin.read(buf, 0, 4);
			int tag = GetAsInt(buf, 0);
			if (tag == CONTAINER_TAG) {
				fin.read(buf, 0, 6);	// Skip 6 bytes
				fin.read(buf, 0, 16);
				UUID storage = UuidFromBytes(buf, 0);
				fin.read(buf, 0, 16);
				UUID agent = UuidFromBytes(buf, 0);
				return new ContainerHandlers(tag, agent, storage);
			}
			else
				return null;
		}
		catch (Exception e) {
			return null;
		}
	}
}
