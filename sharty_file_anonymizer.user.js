// ==UserScript==
// @name			sharty file anonymizer
// @namespace		Violentmonkey Scripts
// @description		Changes file hash and optionally filename
// @match			https://soyjak.st/*
// @grant			none
// @version			1.0
// @author			-
// @require			https://cdn.jsdelivr.net/npm/pako@2.1.0/dist/pako.min.js
// @require			https://cdn.jsdelivr.net/npm/upng-js@2.1.0/UPNG.min.js
// @require			https://cdn.jsdelivr.net/npm/jpeg-js@0.4.4/lib/decoder.min.js
// @require			https://cdn.jsdelivr.net/npm/jpeg-js@0.4.4/lib/encoder.min.js
// ==/UserScript==

(() => {
'use strict';

// --------- SETTINGS ---------
// canvas usage requires canvas permissions
const USE_CANVAS = false;
// use sharty's built in [Options] -> "Strip filenames" to blend in better
const FAKE_FILENAME = false;
const COMPARE_RESULT = false;
// ------ END OF SETTINGS ------

// this makes our script vulnerable to detection by comparing
// clean enviroment (iframe) to window
if (window.self !== window.top) {
	// Don't run in iframes
	return;
}

if (USE_CANVAS) {
	// Hook canvas methods to prevent fingerprinting
	const originalToBlob = HTMLCanvasElement.prototype.toBlob;
	const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;

	HTMLCanvasElement.prototype.toBlob = function(...args) {
		const stack = new Error().stack;
		if (stack.includes('reencodeImageWithCanvas')) {
			return originalToBlob.apply(this, args);
		}
		console.log('[sharty file anonymizer] Blocked unauthorized canvas toBlob access');
		// Silently fail to prevent detection
		return;
	};

	HTMLCanvasElement.prototype.toDataURL = function(...args) {
		const stack = new Error().stack;
		if (stack.includes('reencodeImageWithCanvas')) {
			return originalToDataURL.apply(this, args);
		}
		console.log('[sharty file anonymizer] Blocked unauthorized canvas toDataURL access');
		// Return a blank image to prevent fingerprinting
		return 'data:,';
	};
}

function getRandomIntInclusive(min, max) {
	const minCeiled = Math.ceil(min);
	const maxFloored = Math.floor(max);
	return Math.floor(Math.random() * (maxFloored - minCeiled + 1) + minCeiled);
}

function generateFakeFilename(originalFilename) {
	const lastDot = originalFilename.lastIndexOf('.');
	// Handles files with no extension, and files starting with a dot like .bashrc
	const extension = (lastDot > 0 && lastDot < originalFilename.length - 1) ? originalFilename.substring(lastDot) : '';
	const now = Date.now();
	const yearInMs = 365 * 24 * 60 * 60 * 1000;
	const randomTimestamp = now - getRandomIntInclusive(0, yearInMs);
	const us = String(getRandomIntInclusive(0, 999)).padStart(3, '0');
	return `${randomTimestamp}${us}${extension}`;
}

// find random non-alpha pixel within first 25% of the image and modify it by 50-127
function modifyRandomPixel(data) {
	const pixelCount = data.length / 4;
	const quarterPixelCount = Math.floor(pixelCount * 0.25);

	const pixelIndex = getRandomIntInclusive(0, quarterPixelCount);
	const baseIndex = pixelIndex * 4;

	if (baseIndex + 3 < data.length) {
		const channelOffset = getRandomIntInclusive(0, 2); // 0 for R, 1 for G, 2 for B
		const dataIndex = baseIndex + channelOffset;
		const originalValue = data[dataIndex];
		const modification = getRandomIntInclusive(50, 127);

		// Add or subtract
		if (Math.random() < 0.5) {
			data[dataIndex] = Math.min(255, originalValue + modification);
		} else {
			data[dataIndex] = Math.max(0, originalValue - modification);
		}
	}
}

function reencodeImageWithCanvas(file, newFilename, quality = 0.9) {
	return new Promise((resolve) => {
		console.log('[sharty file anonymizer] Re-encoding the image with canvas');
		const reader = new FileReader();
		reader.addEventListener('load', () => {
			const img = new Image();
			img.onload = () => {
				const cvs = document.createElement('canvas');
				cvs.width = img.width;
				cvs.height = img.height;

				const ctx = cvs.getContext('2d');
				ctx.drawImage(img, 0, 0);

				const imgData = ctx.getImageData(0, 0, cvs.width, cvs.height);
				const data = imgData.data;

				modifyRandomPixel(data);

				ctx.putImageData(imgData, 0, 0);

				cvs.toBlob((blob) => {
					const newFile = new File([blob], newFilename, { type: file.type });
					resolve(newFile);
				}, file.type, quality);
			};

			img.src = reader.result;
		});
		reader.onerror = (err) => {
			console.error('[sharty file anonymizer] FileReader error:', err);
			reject(err);
		};
		reader.readAsDataURL(file);
	});
}

function reencodeImage(file, newFilename, quality = 90) {
	return new Promise((resolve, reject) => {
		console.log('[sharty file anonymizer] Re-encoding the image with libraries');
		const reader = new FileReader();
		reader.onload = () => {
			try {
				const buffer = reader.result;
				let newFileBuffer;

				if (file.type === 'image/png') {
					const img = UPNG.decode(buffer);
					const data = new Uint8Array(UPNG.toRGBA8(img)[0]);
					modifyRandomPixel(data);
					// 0 - cnum: number of colors in the result; 0: all colors (lossless PNG)
					newFileBuffer = UPNG.encode([data.buffer], img.width, img.height, 0);
				} else if (file.type === 'image/jpeg') {
					const jpegData = decode(buffer, { useTArray: true });
					modifyRandomPixel(jpegData.data);
					const newJpegData = encode(jpegData, quality);
					newFileBuffer = newJpegData.data;
				}

				if (newFileBuffer) {
					const newFile = new File([newFileBuffer], newFilename, { type: file.type });
					resolve(newFile);
				}
				reject(new Error(`[sharty file anonymizer] Unsupported file type for re-encoding: ${file.type}`));
			} catch (err) {
				console.error('[sharty file anonymizer] Re-encoding failed:', err);
				reject(err);
			}
		};
		reader.onerror = (err) => {
			console.error('[sharty file anonymizer] FileReader error:', err);
			reject(err);
		};
		reader.readAsArrayBuffer(file);
	});
}

function byteLevelHashChange(file, newFilename) {
	return new Promise((resolve) => {
		const reader = new FileReader();
		reader.addEventListener('load', () => {
			let randomLen = 8;
			// "failed to resize the image" if more
			if (file.type === 'image/gif') {
				randomLen = 2;
			}
			const random = new Uint8Array(randomLen);
			crypto.getRandomValues(random);

			let fileBits = [];

			if (file.type === 'image/gif' || file.type === 'video/webm') {
				const offset = ((file.type === 'video/webm') ? Math.floor(reader.result.byteLength * 0.001) : 2);
				console.log(`[sharty file anonymizer] Modifying ${random.length} bytes at the end-${offset} offset of the file`);

				fileBits = [
					reader.result.slice(0, -offset - random.length),
					random,
					reader.result.slice(-offset),
				];
			} else {
				console.log('[sharty file anonymizer] Adding random bytes to the end of the file');
				fileBits = [reader.result, random];
			}

			const newFile = new File(fileBits, newFilename, { type: file.type });
			resolve(newFile);
		});

		reader.readAsArrayBuffer(file);
	});
}

async function anonFile(file, quality = 0.9) {
	const newFilename = FAKE_FILENAME ? generateFakeFilename(file.name) : file.name;

	if (file.type === 'image/png' || file.type === 'image/jpeg') {
		if (USE_CANVAS) {
			return await reencodeImageWithCanvas(file, newFilename, quality);
		} else {
			return await reencodeImage(file, newFilename, Math.round(quality * 100));
		}
	}

	return await byteLevelHashChange(file, newFilename);
}

async function compareFiles(originalFile, modifiedFile) {
	if (!COMPARE_RESULT) return;

	console.log('[sharty file anonymizer] Comparing original and modified files...');

	try {
		const originalBuffer = await originalFile.arrayBuffer();
		const modifiedBuffer = await modifiedFile.arrayBuffer();

		if (originalBuffer.byteLength === modifiedBuffer.byteLength) {
			console.log('[sharty file anonymizer] File sizes are identical.');
		} else {
			console.log(`[sharty file anonymizer] File sizes differ: ${originalBuffer.byteLength} (original) vs ${modifiedBuffer.byteLength} (modified).`);
		}

		const originalHash = await crypto.subtle.digest('SHA-256', originalBuffer);
		const modifiedHash = await crypto.subtle.digest('SHA-256', modifiedBuffer);

		const originalHashHex = Array.from(new Uint8Array(originalHash)).map(b => b.toString(16).padStart(2, '0')).join('');
		const modifiedHashHex = Array.from(new Uint8Array(modifiedHash)).map(b => b.toString(16).padStart(2, '0')).join('');

		console.log(`[sharty file anonymizer] Original hash: ${originalHashHex}`);
		console.log(`[sharty file anonymizer] Modified hash: ${modifiedHashHex}`);

		if (originalHashHex === modifiedHashHex) {
			console.warn('[sharty file anonymizer] WARNING: File hashes are identical. Anonymization may have failed.');
		} else {
			console.log('[sharty file anonymizer] File hashes differ. Anonymization successful.');
		}
	} catch (error) {
		console.error('[sharty file anonymizer] Error comparing files:', error);
	}
}

const fileHookStartTime = Date.now();
const fileHookMaxWaitTime = 10000; // 10 seconds
const fileHookInterval = setInterval(function() {
	if (typeof window.addFile === 'function') {
		clearInterval(fileHookInterval);

		// Intercept file additions by replacing event handlers
		// Handles multiple and dynamically added dropzones.

		const processAndAddFiles = async (files) => {
			for (const file of files) {
				console.log(`[sharty file anonymizer] Intercepted file: ${file.name}`);
				const anonymizedFile = await anonFile(file);
				if (COMPARE_RESULT) {
					await compareFiles(file, anonymizedFile);
				}
				window.addFile(anonymizedFile);
			}
		};

		// Intercept drag and drop on any dropzone
		document.addEventListener('drop', (event) => {
			event.preventDefault();
			event.stopImmediatePropagation();
			processAndAddFiles(event.dataTransfer.files);
		}, { capture: true });

		// Intercept paste actions that include files
		document.addEventListener('paste', (event) => {
			const items = (event.clipboardData || event.originalEvent.clipboardData).items;
			const fileItems = Array.from(items).filter(item => item.kind === 'file');

			if (fileItems.length > 0) {
				event.preventDefault();
				event.stopImmediatePropagation();
				const files = fileItems.map(item => item.getAsFile());
				processAndAddFiles(files);
			}
		}, { capture: true });

		// Intercept clicks and keypresses on dropzones to open file dialog
		$(document).off('click keypress', '.dropzone'); // Remove original delegated handlers
		$('.dropzone').off('click keypress'); // Also remove directly attached handlers

		$(document).on('click keypress', '.dropzone', function(event) {
			// Replicates the original's logic to proceed on "Enter" keypress OR a click on the hint text.
			const isClickOnHint = (event.which === 1 && String(event.target.className).includes('file-hint'));
			const isEnterPress = (event.which === 13);

			if (isClickOnHint || isEnterPress) {
				event.preventDefault();
				event.stopImmediatePropagation();

				const fileInput = document.createElement('input');
				fileInput.type = 'file';
				fileInput.multiple = true;
				fileInput.addEventListener('change', () => {
					processAndAddFiles(fileInput.files);
				});
				fileInput.click();
			}
		});

		console.log('[sharty file anonymizer] Successfully set up event interception');
	} else if (Date.now() - fileHookStartTime > fileHookMaxWaitTime) {
		clearInterval(fileHookInterval);
		console.log('[sharty file anonymizer] Timed out waiting for window.addFile to become available');
	}
}, 100);

})();
