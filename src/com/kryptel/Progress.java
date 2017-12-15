/*******************************************************************************

  Product:       Kryptel/Java
  File:          Progress.java
  Description:   https://www.kryptel.com/articles/developers/java/kryptel_api.progress.php

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


import static com.kryptel.IProgressCallback.MIN_SIZE_TO_STEP;
import static com.kryptel.IProgressCallback.NO_TOTAL_PROGRESS_BAR;
import static com.kryptel.IProgressCallback.PROGRESS_STEPS;


public final class Progress {
	
	public Progress(IProgressCallback progressFunc, Object arg) {
		this(progressFunc, arg, -1);
	}
	
	public Progress(IProgressCallback progressFunc, Object arg, long totalSize) {
		progress = progressFunc;
		progressArg = arg;
		
		finished = false;
		
		sizeTotal = totalSize;

		if (progress != null && sizeTotal > 0) {
			for (int i = 1; i < PROGRESS_STEPS; i++) totalSteps[i] = (sizeTotal * i) / PROGRESS_STEPS;
			totalSteps[0] = 0;
			totalSteps[PROGRESS_STEPS] = sizeTotal;
			
			currentSizeTotal = 0;
			currentStepTotal = 0;
		}
		
		fileSteps[0] = 0;
		showNextFile = true;
	}
	
	
	public void Discard() throws Exception {			// Must be called to remove progress bar gracefully
		if (progress != null && !finished) {
			if (sizeTotal > 0)
				progress.Callback(progressArg, null, PROGRESS_STEPS, PROGRESS_STEPS);
			else
				progress.Callback(progressArg, null, PROGRESS_STEPS, NO_TOTAL_PROGRESS_BAR);
		}
	}


	public boolean NewFile(String path, long fsize) throws Exception {
		if (finished || progress == null) return true;
		
		if (path.length() > PROGRESS_MAX_PATH_DISPLAYED_LENGTH)
			filePath = "…" + path.substring(path.length() - PROGRESS_MAX_PATH_DISPLAYED_LENGTH + 1);
		else
			filePath = path;
		sizeFile = fsize;
		
		currentSizeFile = 0;
		currentStepFile = 0;
		
		if (sizeFile >= MIN_SIZE_TO_STEP || showNextFile) {
			for (int i = 1; i < PROGRESS_STEPS; i++) fileSteps[i] = (sizeFile * i) / PROGRESS_STEPS;
			fileSteps[PROGRESS_STEPS] = sizeFile;
			showNextFile = false;
			return (sizeTotal > 0) ? progress.Callback(progressArg, filePath, 0, currentStepTotal) : progress.Callback(progressArg, filePath, 0, NO_TOTAL_PROGRESS_BAR);
		}
		else
			return (sizeTotal > 0 && currentStepTotal == 0) ? progress.Callback(progressArg, filePath, 0, 0) : true;
	}


	public boolean Step(long size) throws Exception {
		if (finished || progress == null) return true;
		
		currentSizeFile += size;
		currentSizeTotal += size;
		
		int tstep = 0;
		if (sizeTotal > 0) tstep = CalcStep(currentSizeTotal, currentStepTotal, totalSteps);
		
		if (sizeFile >= MIN_SIZE_TO_STEP ||
				currentSizeFile == sizeFile ||
				(sizeTotal > 0 && tstep != currentStepTotal)) {
	
			int fstep;
			if (currentSizeFile < sizeFile) {
				fstep = CalcStep(currentSizeFile, currentStepFile, fileSteps);
				if (currentStepFile == fstep) return true;		// Bar is not moving
			}
			else
				fstep = PROGRESS_STEPS;
			
			boolean res;
	
			if (sizeTotal > 0) {
				if (sizeFile >= MIN_SIZE_TO_STEP || tstep != currentStepTotal) {
					res = progress.Callback(progressArg, filePath, fstep, tstep);
					if (sizeFile < MIN_SIZE_TO_STEP) showNextFile = true;		// File is too small, but total bar moved - show the next file to add some life
				}
				else
					res = true;
					
				if (currentSizeTotal == sizeTotal) {
					assert (currentSizeFile == sizeFile);
					finished = true;			// Mark processing finished
				}
				else {
					currentStepFile = fstep;
					currentStepTotal = tstep;
				}
			}
			else {		// No total bar
				res = progress.Callback(progressArg, filePath, fstep, NO_TOTAL_PROGRESS_BAR);
	
				if (currentSizeFile == sizeFile) {
					assert (fstep == PROGRESS_STEPS);
					finished = true;			// Mark processing finished
				}
				else
					currentStepFile = fstep;
			}
			
			return res;
		}
		else {
			assert (currentSizeTotal != sizeTotal || sizeTotal == 0);
			return true;
		}
	}

	
  //
  // Private data and methods
  //
	
	private static final int PROGRESS_MAX_PATH_DISPLAYED_LENGTH = 28;
	
	private IProgressCallback progress;
	private Object progressArg;
	
	boolean finished;

	private long sizeTotal;
	private long[] totalSteps = new long [PROGRESS_STEPS + 1];
	private long currentSizeTotal;
	private int currentStepTotal;
	
	private long sizeFile;
	private long[] fileSteps = new long [PROGRESS_STEPS + 1];
	private long currentSizeFile;
	private int currentStepFile;
	
	String filePath;
	boolean showNextFile;


	private int CalcStep(long curPos, int curStep, long[] steps) {
		for ( ; curStep < PROGRESS_STEPS && curPos >= steps[curStep + 1]; curStep++);
		return curStep;
	}
}
