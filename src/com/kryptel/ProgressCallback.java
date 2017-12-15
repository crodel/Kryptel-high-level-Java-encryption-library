/*******************************************************************************

  Product:       Kryptel/Java
  File:          ProgressCallback.java
  Description:   https://www.kryptel.com/articles/developers/java/kryptel_api.progresscallback.php

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


import com.kryptel.bslx.BooleanFlag;


//
// This helper class encapsulates IProgressCallback and is intended for use by client application programs
//


public class ProgressCallback implements IProgressCallback {
	
	public interface IProgressDialog {
		void CreateProgress(Object arg, String strTitle, boolean totalBar, BooleanFlag abortRequested) throws Exception;
		void SetProgressMessage(Object arg, String strMessage) throws Exception;
		void SetProgressStep(Object arg, int fileStep, int totalStep) throws Exception;
		void DismissProgress(Object arg) throws Exception;
	}
	
	
	public ProgressCallback(String title, IProgressDialog dialog, BooleanFlag abortRequested) {
		progressTitle = title;
		progressDialog = dialog;
		if (abortRequested != null) abortRequested.set(false);
		this.abortRequested = abortRequested;
	}

	
	//
	// IProgressCallback
	//
	
	public boolean Callback(Object arg, String curFile, int stepFile, int stepTotal) throws Exception {
		if (abortRequested != null && abortRequested.is_set()) return false;
		
    if (stepFile == 0) {		// New file, and possibly new progress dialog
      if (stepTotal == 0 || stepTotal == IProgressCallback.NO_TOTAL_PROGRESS_BAR) {					// Create new progress dialog
      	progressDialog.CreateProgress(arg, progressTitle, stepTotal == 0, abortRequested);
      	dismissed = false;
      }
      else if (dismissed)
      	return true;
      
      if (curFile != null) progressDialog.SetProgressMessage(arg, curFile);
      progressDialog.SetProgressStep(arg, 0, stepTotal);
    }

    else if (stepFile == IProgressCallback.PROGRESS_STEPS &&
             (stepTotal == IProgressCallback.PROGRESS_STEPS || stepTotal == IProgressCallback.NO_TOTAL_PROGRESS_BAR)) {
      progressDialog.SetProgressStep(arg, IProgressCallback.PROGRESS_STEPS, stepTotal);
      progressDialog.DismissProgress(arg);
      dismissed = true;
		}
		else {
			if (dismissed) return true;
			progressDialog.SetProgressStep(arg, stepFile, stepTotal);
		}

    return abortRequested == null || !abortRequested.is_set();
	}
	
	
	//
	// Private data
	//
	
	private boolean dismissed = false;
	private String progressTitle;
	private IProgressDialog progressDialog;
	private BooleanFlag abortRequested;
}
