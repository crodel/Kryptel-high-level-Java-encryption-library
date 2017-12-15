/*******************************************************************************

  Product:       Kryptel/Java
  File:          Targets.java
  Description:   https://www.kryptel.com/articles/developers/java/bslx.targets.php
 
  Copyright (c) 2017 Inv Softworks LLC, http://www.kryptel.com

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


import java.io.File;
import java.util.HashMap;

import com.kryptel.Message;


public final class Targets {

	public static final int TARGET_UNKNOWN								= -1;
	
	public static final int TARGET_DEFAULT								= 0;
	public static final int TARGET_ASK_USER								= 0;
			
	// Windows drives
	public static final int TARGET_DRIVE_A								= 1;
	public static final int TARGET_DRIVE_B								= 2;
	public static final int TARGET_DRIVE_C								= 3;
	public static final int TARGET_DRIVE_D								= 4;
	public static final int TARGET_DRIVE_E								= 5;
	public static final int TARGET_DRIVE_F								= 6;
	public static final int TARGET_DRIVE_G								= 7;
	public static final int TARGET_DRIVE_H								= 8;
	public static final int TARGET_DRIVE_I								= 9;
	public static final int TARGET_DRIVE_J								= 10;
	public static final int TARGET_DRIVE_K								= 11;
	public static final int TARGET_DRIVE_L								= 12;
	public static final int TARGET_DRIVE_M								= 13;
	public static final int TARGET_DRIVE_N								= 14;
	public static final int TARGET_DRIVE_O								= 15;
	public static final int TARGET_DRIVE_P								= 16;
	public static final int TARGET_DRIVE_Q								= 17;
	public static final int TARGET_DRIVE_R								= 18;
	public static final int TARGET_DRIVE_S								= 19;
	public static final int TARGET_DRIVE_T								= 20;
	public static final int TARGET_DRIVE_U								= 21;
	public static final int TARGET_DRIVE_V								= 22;
	public static final int TARGET_DRIVE_W								= 23;
	public static final int TARGET_DRIVE_X								= 24;
	public static final int TARGET_DRIVE_Y								= 25;
	public static final int TARGET_DRIVE_Z								= 26;
			
	public static final int TARGET_STORAGE_ROOT						= 27;
	public static final int TARGET_NETWORK_ROOT						= 28;
			
	// Windows-specific targets
	public static final int TARGET_APPDATA								= 29;
	public static final int TARGET_COMMON_APPDATA					= 30;
	public static final int TARGET_LOCAL_APPDATA					= 31;
	public static final int TARGET_DESKTOP								= 32;
	public static final int TARGET_COMMON_DESKTOP					= 33;
	public static final int TARGET_DOCUMENTS							= 34;
	public static final int TARGET_COMMON_DOCUMENTS				= 35;
	public static final int TARGET_FAVORITES							= 36;
	public static final int TARGET_COMMON_FAVORITES				= 37;
	public static final int TARGET_MUSIC									= 38;
	public static final int TARGET_COMMON_MUSIC						= 39;
	public static final int TARGET_PICTURES								= 40;
	public static final int TARGET_COMMON_PICTURES				= 41;
	public static final int TARGET_PROGRAMS								= 42;
	public static final int TARGET_COMMON_PROGRAMS				= 43;
	public static final int TARGET_STARTUP								= 44;
	public static final int TARGET_COMMON_STARTUP					= 45;
	public static final int TARGET_STARTMENU							= 46;
	public static final int TARGET_COMMON_STARTMENU				= 47;
	public static final int TARGET_TEMPLATES							= 48;
	public static final int TARGET_COMMON_TEMPLATES				= 49;
	public static final int TARGET_VIDEOS									= 50;
	public static final int TARGET_COMMON_VIDEOS					= 51;
	public static final int TARGET_TEMP										= 52;
	
	// Targets included for compatibility with older versions (don't use unless really necessary).
	// Although the current versions still recognize these targets, their support will likely be
	// removed in future versions for security reasons.
	public static final int TARGET_COOKIES								= 53;
	public static final int TARGET_HISTORY								= 54;
	public static final int TARGET_RECENT									= 55;
	public static final int TARGET_PROGRAM_FILES					= 56;
	public static final int TARGET_COMMON_PROGRAM_FILES		= 57;
	public static final int TARGET_WINDOWS								= 58;
	public static final int TARGET_SYSTEM									= 59;
	
	public static final int TARGET_ENUM_SIZE							= TARGET_SYSTEM + 1;		// Dummy target to use as enumeration's size

	
	public static final class TargetedPath {
		public int target;
		public String path;
	}
	
	public interface ITargetedPathEncoder {
		String GetTargetPath(int target) throws Exception;
		TargetedPath RecognizeTarget(String path) throws Exception;
	}
	
	
	public static final void SetEncoder(ITargetedPathEncoder enc) {
		encoder = enc;
	}

	
	public static final String GetTargetName(int target) {
		return TargetNames[target];
	}
	
	
	public static final int GetTargetCode(String target) {
		Integer t = TargetCodes.get(target);
		return (t != null) ? t : TARGET_UNKNOWN;
	}
	
	
	public static final String GetTargetPath(int target) throws Exception {
		if (target == TARGET_UNKNOWN) throw new Exception(Message.Get(Message.Code.UnknownTarget));

		if (encoder != null)
			return encoder.GetTargetPath(target);
		else if (target == TARGET_DEFAULT)
			return "";
		else if (target == TARGET_STORAGE_ROOT)
			return File.separator;
		else
			return File.separator + GetTargetName(target) + File.separator;
	}
	
	
	public static final TargetedPath RecognizeTarget(String path) throws Exception {
		if (encoder == null) {
			TargetedPath tp = new TargetedPath();
			if (path.charAt(1) == ':') {
				tp.target = (path.toLowerCase().charAt(0) - 'a') + TARGET_DRIVE_A;
				tp.path = (path.charAt(2) == '/' || path.charAt(2) == '\\') ? path.substring(3) : path.substring(2);
			}
			else {
				tp.target = TARGET_STORAGE_ROOT;
				tp.path = (path.charAt(0) == '/' || path.charAt(0) == '\\') ? path.substring(1) : path;
			}
			return tp;
		}
		else
			return encoder.RecognizeTarget(path);
	}
	
	
	//
	// Private data and methods
	//
	
	private static String[] TargetNames;
	private static HashMap<String, Integer> TargetCodes;
	private static String letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	
	private static ITargetedPathEncoder encoder = null;
	
	static {
		TargetNames = new String [TARGET_ENUM_SIZE];
		TargetNames[TARGET_DEFAULT] = "Default Target";
		TargetNames[TARGET_STORAGE_ROOT] = "Device Storage Root";
		TargetNames[TARGET_NETWORK_ROOT] = "Network Share";
		TargetNames[TARGET_APPDATA] = "Application Data";
		TargetNames[TARGET_COMMON_APPDATA] = "Common Application Data";
		TargetNames[TARGET_LOCAL_APPDATA] = "Local Application Data";
		TargetNames[TARGET_DESKTOP] = "Desktop";
		TargetNames[TARGET_COMMON_DESKTOP] = "Common Desktop";
		TargetNames[TARGET_DOCUMENTS] = "My Documents";
		TargetNames[TARGET_COMMON_DOCUMENTS] = "Common Documents";
		TargetNames[TARGET_FAVORITES] = "Favorites";
		TargetNames[TARGET_COMMON_FAVORITES] = "Common Favorites";
		TargetNames[TARGET_MUSIC] = "My Music";
		TargetNames[TARGET_COMMON_MUSIC] = "Common Music";
		TargetNames[TARGET_PICTURES] = "My Pictures";
		TargetNames[TARGET_COMMON_PICTURES] = "Common Pictures";
		TargetNames[TARGET_PROGRAMS] = "Programs";
		TargetNames[TARGET_COMMON_PROGRAMS] = "Common Programs";
		TargetNames[TARGET_STARTUP] = "Startup";
		TargetNames[TARGET_COMMON_STARTUP] = "Common Startup";
		TargetNames[TARGET_STARTMENU] = "Start Menu";
		TargetNames[TARGET_COMMON_STARTMENU] = "Common Start Menu";
		TargetNames[TARGET_TEMPLATES] = "Templates";
		TargetNames[TARGET_COMMON_TEMPLATES] = "Common Templates";
		TargetNames[TARGET_VIDEOS] = "My Videos";
		TargetNames[TARGET_COMMON_VIDEOS] = "Common Video";
		TargetNames[TARGET_TEMP] = "Temporary Folder";
		TargetNames[TARGET_COOKIES] = "Cookies";
		TargetNames[TARGET_HISTORY] = "Internet History";
		TargetNames[TARGET_RECENT] = "Recent Documents";
		TargetNames[TARGET_PROGRAM_FILES] = "Program Files";
		TargetNames[TARGET_COMMON_PROGRAM_FILES] = "Common Program Files";
		TargetNames[TARGET_WINDOWS] = "Windows Folder";
		TargetNames[TARGET_SYSTEM] = "System Folder";
		
		TargetCodes = new HashMap<String, Integer>(TARGET_ENUM_SIZE);
		TargetCodes.put("Default Target", TARGET_DEFAULT);
		TargetCodes.put("User-specified", TARGET_ASK_USER);
		TargetCodes.put("Device Storage Root", TARGET_STORAGE_ROOT);
		TargetCodes.put("Network Share", TARGET_NETWORK_ROOT);
		TargetCodes.put("Application Data", TARGET_APPDATA);
		TargetCodes.put("Common Application Data", TARGET_COMMON_APPDATA);
		TargetCodes.put("Local Application Data", TARGET_LOCAL_APPDATA);
		TargetCodes.put("Desktop", TARGET_DESKTOP);
		TargetCodes.put("Common Desktop", TARGET_COMMON_DESKTOP);
		TargetCodes.put("My Documents", TARGET_DOCUMENTS);
		TargetCodes.put("Common Documents", TARGET_COMMON_DOCUMENTS);
		TargetCodes.put("Favorites", TARGET_FAVORITES);
		TargetCodes.put("Common Favorites", TARGET_COMMON_FAVORITES);
		TargetCodes.put("My Music", TARGET_MUSIC);
		TargetCodes.put("Common Music", TARGET_COMMON_MUSIC);
		TargetCodes.put("My Pictures", TARGET_PICTURES);
		TargetCodes.put("Common Pictures", TARGET_COMMON_PICTURES);
		TargetCodes.put("Programs", TARGET_PROGRAMS);
		TargetCodes.put("Common Programs", TARGET_COMMON_PROGRAMS);
		TargetCodes.put("Startup", TARGET_STARTUP);
		TargetCodes.put("Common Startup", TARGET_COMMON_STARTUP);
		TargetCodes.put("Start Menu", TARGET_STARTMENU);
		TargetCodes.put("Common Start Menu", TARGET_COMMON_STARTMENU);
		TargetCodes.put("Templates", TARGET_TEMPLATES);
		TargetCodes.put("Common Templates", TARGET_COMMON_TEMPLATES);
		TargetCodes.put("My Videos", TARGET_VIDEOS);
		TargetCodes.put("Common Video", TARGET_COMMON_VIDEOS);
		TargetCodes.put("Temporary Folder", TARGET_TEMP);
		TargetCodes.put("Cookies", TARGET_COOKIES);
		TargetCodes.put("Internet History", TARGET_HISTORY);
		TargetCodes.put("Recent Documents", TARGET_RECENT);
		TargetCodes.put("Program Files", TARGET_PROGRAM_FILES);
		TargetCodes.put("Common Program Files", TARGET_COMMON_PROGRAM_FILES);
		TargetCodes.put("Windows Folder", TARGET_WINDOWS);
		TargetCodes.put("System Folder", TARGET_SYSTEM);

		for (int i = 0; i < 26; i++) {
			String targetName = "Drive " + letters.charAt(i);
			TargetNames[i + 1] = targetName;
			TargetCodes.put(targetName, i + 1);
		}
	}
	
}
