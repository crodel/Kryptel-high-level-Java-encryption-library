/*******************************************************************************

  Product:       Kryptel/Java
  File:          Message.java
  Description:   https://www.kryptel.com/articles/developers/java/kryptel_api.message.php

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


public final class Message {
	public enum Code {
		// Common errors
		UserAbort, WrongKey, CompNotFound, UnsupportedCap, InvalidArg, InvalidState,
		KeyMustBeSet, NotBlockSizeMultiple, InvalidCipherStreamHeader, InvalidCipherStream,
		InvalidKeySize, InvalidBlockSize, InvalidRounds, MacBaseNotSet, InvalidMacBase,
		EmptyPassword, UnsupportedKeyMaterial, InvalidKeyMaterial,
		FileExpected, FolderExpected, FileConflictingName, FolderConflictingName,
		
		// Kryptel errors
		InvalidContainer, OldHandlerVersion, InvalidContainerSize, EncryptorNotFound,

		// Silver Key errors
		BaseFileRenameError, UnknownTarget,
		InvalidParcel, CorruptedParcel, TamperedPacel, OldVersion, IncompatibleVersion, WrongExtractor,
		UnknownScriptCommand,

		// Web Storage errors
		WrongResponseCode, JSONExpected, UnrecognizedJSON, UnknownErrorJSON,
		ConcurrentOps, CantRunBrowser, AuthResponse, ConnectionTimeout,
		WrongHeaderData, PrematureEOF,

		// Web Storage authorization default html pages
		AuthSucceeded, AuthFailed, AuthNotFound,
		
		// HTTP status codes
		Http400, Http401, Http403, Http404, Http405, Http406, Http409,
		Http410, Http411, Http412, Http413, Http415, Http416, Http422, Http429,
		Http500, Http501, Http503, Http507, Http509,
		HttpUnknown,
		
		// Various messages shown via INotification
		ParcelIntegrity, DetectTampering, VerifyingPassword, FilesSkipped
	};

	public interface ILocalizedMessage {
		String Get(Code code);
	}
	
	
	//
	// Methods
	//
	
	public static void Localize(ILocalizedMessage localizer) { messageLocalizer = localizer; }
	
	public static String Get(Code code) {
		return (messageLocalizer == null) ? GetDefaultMessage(code) : messageLocalizer.Get(code);
	}
	
	public static String GetDefaultMessage(Code code) {
		return MessageList[code.ordinal()];
	}
	
	
	//
	// Private data
	//
	
	private static ILocalizedMessage messageLocalizer = null;
	
	// Default (non-localized) messages

	private static String[] MessageList;
	
	static {
		// Common errors
		MessageList = new String [Code.values().length];
		MessageList[Code.UserAbort.ordinal()] = "Operation aborted.";
		MessageList[Code.WrongKey.ordinal()] = "Wrong password or key.";
		MessageList[Code.CompNotFound.ordinal()] = "Requested component not found.";
		MessageList[Code.UnsupportedCap.ordinal()] = "Requested capability is not supported in this version/edition.";
		MessageList[Code.InvalidArg.ordinal()] = "Invalid argument specified.";
		MessageList[Code.InvalidState.ordinal()] = "Invalid component state.";
		MessageList[Code.KeyMustBeSet.ordinal()] = "Encryption key has not been set.";
		MessageList[Code.NotBlockSizeMultiple.ordinal()] = "Data size is not a multiple of cipher block size.";
		MessageList[Code.InvalidCipherStreamHeader.ordinal()] = "Corrupted cipher data stream (invalid header).";
		MessageList[Code.InvalidCipherStream.ordinal()] = "Corrupted cipher data stream.";
		MessageList[Code.InvalidKeySize.ordinal()] = "Invalid key size.";
		MessageList[Code.InvalidBlockSize.ordinal()] = "Invalid block size.";
		MessageList[Code.InvalidRounds.ordinal()] = "Invalid number of rounds.";
		MessageList[Code.MacBaseNotSet.ordinal()] = "MAC base component must be set up.";
		MessageList[Code.InvalidMacBase.ordinal()] = "Invalid type of MAC base component.";
		MessageList[Code.EmptyPassword.ordinal()] = "Empty password is not allowed.";
		MessageList[Code.UnsupportedKeyMaterial.ordinal()] = "Unsupported key material.";
		MessageList[Code.InvalidKeyMaterial.ordinal()] = "Invalid key material requested.";
		MessageList[Code.FileExpected.ordinal()] = "Folder specified but a file is expected.";
		MessageList[Code.FolderExpected.ordinal()] = "File specified but a folder is expected.";
		MessageList[Code.FileConflictingName.ordinal()] = "Can't create file because directory with such name already exists.";
		MessageList[Code.FolderConflictingName.ordinal()] = "Can't create directory because file with such name already exists.";
		
		// Kryptel errors
		MessageList[Code.InvalidContainer.ordinal()] = "Invalid or corrupted container file.";
		MessageList[Code.OldHandlerVersion.ordinal()] = "Container file requires newer version of storage handler - please upgrade your software.";
		MessageList[Code.InvalidContainerSize.ordinal()] = "Container has invalid size (probably corrupted).";
		MessageList[Code.EncryptorNotFound.ordinal()] = "The required encrypted storage handler not found.";

		// Silver Key errors
		MessageList[Code.BaseFileRenameError.ordinal()] = "Unable to rename parcel's base file (too many copies?).";
		MessageList[Code.UnknownTarget.ordinal()] = "Unknown or unsupported target.";
		MessageList[Code.InvalidParcel.ordinal()] = "Not a valid Silver Key parcel.";
		MessageList[Code.CorruptedParcel.ordinal()] = "Corrupted Silver Key parcel.";
		MessageList[Code.TamperedPacel.ordinal()] = "The parcel has been tampered with.";
		MessageList[Code.OldVersion.ordinal()] = "A newer extractor version is needed to decrypt this parcel.";
		MessageList[Code.IncompatibleVersion.ordinal()] = "This parcel was created with incomatible (outdated) Silver Key version.";
		MessageList[Code.WrongExtractor.ordinal()] = "Unsupported encryption method.";
		MessageList[Code.UnknownScriptCommand.ordinal()] = "Unknown command encountered in parcel script.";

		// Web Storage errors
		MessageList[Code.WrongResponseCode.ordinal()] = "Server returned unexpected status code.";
		MessageList[Code.JSONExpected.ordinal()] = "JSON data expected but nothing received.";
		MessageList[Code.UnrecognizedJSON.ordinal()] = "Unrecognized JSON data received.";
		MessageList[Code.UnknownErrorJSON.ordinal()] = "Got unrecognized error descriptor.";
		MessageList[Code.ConcurrentOps.ordinal()] = "Concurrent operations not supported.";
		MessageList[Code.CantRunBrowser.ordinal()] = "Failed to open the default Web browser.";
		MessageList[Code.AuthResponse.ordinal()] = "Can't identify response from authorization server.";
		MessageList[Code.ConnectionTimeout.ordinal()] = "Unable to connect (timeout).";
		MessageList[Code.WrongHeaderData.ordinal()] = "Received HTTP header contains wrong data.";
		MessageList[Code.PrematureEOF.ordinal()] = "Premature end of file.";

		// Web Storage messages
		MessageList[Code.AuthSucceeded.ordinal()] = "<html><head><title>Kryptel and Silver Key Web Storage Handler</title>" +
				"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />" +
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" /></head>" +
				"<body style=\"margin: 30px\"><h1>Authorization succeeded</h1><p>We have got the permission to access your Web storage.</p>" +
				"<p>Now you can close this window.</p><script type=\"text/javascript\">close();</script></body></html>\r\n\r\n"; 
				
		MessageList[Code.AuthFailed.ordinal()] = "<html><head><title>Kryptel and Silver Key Web Storage Handler</title>" +
				"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />" +
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" /></head>" +
				"<body style=\"margin: 30px\"><h1>Authorization failed</h1><p>Your Web storage has denied us the permission to access your files." +
				"</p><p>Error code: &quot;<b>%s</b>&quot;</p></body></html>\r\n\r\n";

		MessageList[Code.AuthNotFound.ordinal()] = "<html><head><title>404 Not Found</title>" +
				"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />" +
				"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" /></head>" +
				"<body><h1>Not Found</h1><p>The requested resource was not found on this server.</p></body></html>\r\n\r\n";

		// HTTP status codes
		MessageList[Code.Http400.ordinal()] = "Bad Request";
		MessageList[Code.Http401.ordinal()] = "Unauthorized";
		MessageList[Code.Http403.ordinal()] = "Forbidden";
		MessageList[Code.Http404.ordinal()] = "Not Found";
		MessageList[Code.Http405.ordinal()] = "Method Not Allowed";
		MessageList[Code.Http406.ordinal()] = "Not Acceptable";
		MessageList[Code.Http409.ordinal()] = "Conflict";
		MessageList[Code.Http410.ordinal()] = "Gone";
		MessageList[Code.Http411.ordinal()] = "Length Required";
		MessageList[Code.Http412.ordinal()] = "Precondition Failed";
		MessageList[Code.Http413.ordinal()] = "Request Entity Too Large";
		MessageList[Code.Http415.ordinal()] = "Unsupported Media Type";
		MessageList[Code.Http416.ordinal()] = "Requested Range Not Satisfiable";
		MessageList[Code.Http422.ordinal()] = "Unprocessable Entity";
		MessageList[Code.Http429.ordinal()] = "Too Many Requests";
		MessageList[Code.Http500.ordinal()] = "Internal Server Error";
		MessageList[Code.Http501.ordinal()] = "Not Implemented";
		MessageList[Code.Http503.ordinal()] = "Service Unavailable";
		MessageList[Code.Http507.ordinal()] = "Insufficient Storage";
		MessageList[Code.Http509.ordinal()] = "Bandwidth Limit Exceeded";
		MessageList[Code.HttpUnknown.ordinal()] = "Unknown HTTP code";
		
		// Various messages
		MessageList[Code.ParcelIntegrity.ordinal()] = "Checking parcel integrity...";
		MessageList[Code.DetectTampering.ordinal()] = "Detecting parcel tampering...";
		MessageList[Code.VerifyingPassword.ordinal()] = "Verifying password...";
		MessageList[Code.FilesSkipped.ordinal()] = "Some files have been skipped because such files already exist.";
	}
}
