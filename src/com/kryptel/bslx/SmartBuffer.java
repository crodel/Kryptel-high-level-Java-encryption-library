/*******************************************************************************

  Product:       Kryptel/Java
  File:          SmartBuffer.java
  Description:   https://www.kryptel.com/articles/developers/java/bslx.smartbuffer.php

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


public class SmartBuffer {
	public SmartBuffer() { }

	public SmartBuffer(byte[] src, int start, int len) {
		firstElement = lastElement = new BufferElement(src, start, len);
	}
	
	public synchronized int Size() {
		BufferElement p = firstElement;
		int total = 0;
		while (p != null) {
			total += p.Size();
			p = p.nextElement;
		}
		return total;
	}
	
	public synchronized void Empty() {
		firstElement = lastElement = null;
	}
	
	public void Store(byte[] buf) { Store(buf, 0, buf.length); }
	
	public synchronized void Store(byte[] buf, int start, int len) {
		BufferElement elem = new BufferElement(buf, start, len);
		if (lastElement != null) {
			assert (firstElement != null);
			lastElement.nextElement = elem;
			lastElement = elem;
		}
		else {
			assert (firstElement == null);
			firstElement = lastElement = elem;
		}
	}
	
	public synchronized byte[] Retrieve(int len) {
		int sz = Math.min(len, Size());
		byte[] ret = new byte [sz];
		Retrieve(ret, 0, sz);
		return ret;
	}
	
	public synchronized int Retrieve(byte[] buf, int start, int len) {
		int nr, n, k;
		nr = n = Math.min(len, Size());

		while (n > 0) {
			k = firstElement.Retrieve(buf, start, n);
			start += k;
			n -= k;
			if (firstElement.Size() == 0) {
				firstElement = firstElement.nextElement;
				if (firstElement == null) lastElement = null;
			}
		}
		return nr;
	}

	public synchronized void Unretrieve(byte[] buf, int start, int len) {
		BufferElement elem = new BufferElement(buf, start, len);
		elem.nextElement = firstElement;
		firstElement = elem;
		if (lastElement == null) lastElement = elem;
	}
	
	// Retrieve data without removing them from the buffer
	public synchronized int Peek(byte[] buf, int start, int len) {
		BufferElement p = firstElement;
		int nr, n, k;
		nr = n = Math.min(len, Size());

		while (n > 0) {
			k = p.Retrieve(buf, start, n);
			start += k;
			n -= k;
			p = p.nextElement;
		}
		return nr;
	}
	
	public synchronized int SkipBytes(int len) {
		int nr, n, k;
		nr = n = Math.min(len, Size());

		while (n > 0) {
			k = firstElement.SkipBytes(n);
			n -= k;
			if (firstElement.Size() == 0) {
				firstElement = firstElement.nextElement;
				if (firstElement == null) lastElement = null;
			}
		}
		return nr;
	}
	
	public synchronized byte[] Merge() {
		if (firstElement != lastElement || firstElement.index != 0) {
			int n = Size();
			byte buf[] = new byte [n];
			Retrieve(buf, 0, n);
			firstElement = lastElement = new BufferElement(buf);
		}
		return firstElement.buffer;
	}

	
	protected BufferElement firstElement, lastElement;
	
	
	//
	// BufferElement
	//

	protected static final class BufferElement {
		protected BufferElement nextElement;
		protected byte[] buffer;
		protected int index = 0;		// Start position
		
		protected BufferElement(byte[] buf, int start, int len) {
			buffer = new byte [len];
			System.arraycopy(buf, start, buffer, 0, len);
		}
		
		// ATTN: This constructor attaches a buffer; for copying use the previous constructor
		protected BufferElement(byte[] buf) {
			buffer = buf;
			index = 0;
		}
		
		protected int Size() { return buffer.length - index; }
		
		protected int Retrieve(byte[] dest, int start, int len) {
			int rlen = Math.min(len, Size());
			if (rlen > 0) {
				System.arraycopy(buffer, index, dest, start, rlen);
				index += rlen;
			}
			return rlen;
		}
		
		protected int SkipBytes(int len) {
			int slen = Math.min(len, Size());
			if (slen > 0) index += slen;
			return slen;
		}
	}
}
