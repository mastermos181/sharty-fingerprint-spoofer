# You might need to install the following libraries first:
# pip install curl_cffi pycryptodome Pillow
from curl_cffi import requests
from curl_cffi.const import CurlOpt, CurlIpResolve
import json
import sys
import re
import random
import string
import time
import os
import base64
from Crypto.Cipher import AES
import mimetypes
import argparse
import codecs

sys.path.insert(0, "../libs")
from fingerprints import Chrome, Firefox, Safari, BrowserTypes, PlatformTypes, get_browser_config, get_unmasked_renderer
from curl_cffi_wrapper import HeaderAwareSession
from debug_fingerprint import debug_fingerprint
from file_utils import change_file_hash
from text_utils import insert_zero_width_char_in_each_word

# sometimes you get integrity check failed but the post actually goes through

# apply this patch to curl_cffi to fix extra_fp getting overwritten
# https://github.com/lexiforest/curl_cffi/pull/680

REFETCH_IP_ON_EACH_CALL = False
# fingerprints cache is based on ips, to get ip we can either
# call third party api, or use sharty's /inc/ip.php
# but since we don't know our ip we can't reuse fingerprint
# so fingerprint between ip request and subsequent requests
# will differ
USE_IP_API = True
# set to false to generate new fingerprint on each session
REUSE_FINGERPRINT = True
CACHE_SIZE = 4
CACHE_FILENAME = 'poster.cache'

def load_entries():
	if os.path.exists(CACHE_FILENAME):
		try:
			with open(CACHE_FILENAME, 'r', encoding='utf-8') as f:
				return json.load(f)
		except (json.JSONDecodeError, IOError) as e:
			print(f"Warning: Could not load cache file '{CACHE_FILENAME}': {e}")
			return []
	return []

def save_entries(entries):
	try:
		with open(CACHE_FILENAME, 'w', encoding='utf-8') as f:
			json.dump(entries, f, separators=(',', ':'))
	except IOError as e:
		print(f"Warning: Could not save cache to file '{CACHE_FILENAME}': {e}")


def get_default_request_args(proxy=None):
	"""Returns a dictionary with default arguments for requests."""
	args = {
		"curl_options": {
			CurlOpt.IPRESOLVE: CurlIpResolve.V4
		}
	}
	if proxy:
		args["proxy"] = proxy
	return args


g_cached_ip = None
g_cached_ip_api_response = None

def get_public_ip(request_args=None):
	"""Fetches the current public IP, with in-memory caching for the session."""
	global g_cached_ip, g_cached_ip_api_response
	if request_args is None:
		request_args = {}
	if not REFETCH_IP_ON_EACH_CALL and g_cached_ip:
		return g_cached_ip

	if USE_IP_API:
		# if we have a response and we are not forced to refetch, we can derive the IP from it.
		if not REFETCH_IP_ON_EACH_CALL and g_cached_ip_api_response:
			print("Using cached public IP")
			current_ip = g_cached_ip_api_response['query']
		else:
			print("Fetching proxy public IP and time zone from ip-api.com...")
			ip_response = requests.get("http://ip-api.com/json/?fields=status,message,query,countryCode,offset", **request_args)
			ip_response.raise_for_status()
			data = ip_response.json()
			if data.get('status') != 'success':
				raise ValueError(f"Failed to get IP from ip-api.com: {data.get('message')}")
			if 'query' not in data:
				raise ValueError("ip-api.com response did not contain 'query' (the IP address)")
			g_cached_ip_api_response = data
			current_ip = data['query']
	else:
		print("Fetching proxy public IP...")
		ip_response = requests.get("https://soyjak.st/inc/ip.php", **request_args)
		ip_response.raise_for_status()
		current_ip = ip_response.text.strip()
		if not current_ip:
			raise ValueError("Failed to get IP from soyjak.st/inc/ip.php: response was empty")
	
	print(f"IP fetched: {current_ip}")
	g_cached_ip = current_ip
	return current_ip

def timezone_to_offset(tz_str):
	"""Converts a time zone string like '-08:00' to a minute offset."""
	sign = -1 if tz_str.startswith('-') else 1
	parts = tz_str.replace('+', '-').split('-')[-1].split(':')
	hours = int(parts[0])
	minutes = int(parts[1]) if len(parts) > 1 else 0
	return (hours * 60 + minutes) * -sign

def get_timezone_for_ip(ip, request_args=None):
	"""Fetches the time zone for a specific IP address."""
	global g_cached_ip_api_response
	if request_args is None:
		request_args = {}
	if USE_IP_API:
		if g_cached_ip_api_response and g_cached_ip_api_response.get('query') == ip:
			print("Using cached response from ip-api.com for time zone")
			geo_data = g_cached_ip_api_response
		else:
			print("Fetching IP time zone from ip-api.com...")
			geo_response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,countryCode,offset", **request_args)
			geo_response.raise_for_status()
			geo_data = geo_response.json()
			if geo_data.get('status') != 'success':
				raise ValueError(f"Failed to get time zone from ip-api.com: {geo_data.get('message')}")

		country_code = geo_data.get("countryCode")
		if not country_code:
			raise ValueError("ip-api.com response did not contain 'countryCode'")

		# offset is in seconds from UTC
		offset_seconds = geo_data.get("offset")
		if offset_seconds is None:
			raise ValueError("ip-api.com response did not contain 'offset'")

		# The script wants minutes, but inverted.
		# e.g. -25200 seconds is UTC-7, which should be 420 minutes.
		tz_offset = -int(offset_seconds / 60)
	else:
		print(f"Fetching IP time zone for {ip}...")
		geo_response = requests.get(f"https://api.ip2location.io/?ip={ip}", **request_args)
		geo_response.raise_for_status()
		geo_data = geo_response.json()

		if 'error' in geo_data:
			raise ValueError(f"ip2location.io returned an error: {geo_data['error']}")

		country_code = geo_data.get("country_code")
		if not country_code:
			raise ValueError("Failed to get IP country code from api.ip2location.io: no country code returned or value is empty")

		time_zone_str = geo_data.get("time_zone")
		if not time_zone_str:
			raise ValueError("Failed to get IP time zone from api.ip2location.io: no time zone returned or value is empty")

		tz_offset = timezone_to_offset(time_zone_str)

	print(f"IP country: {country_code}, time zone offset (minutes): {tz_offset}")
	return tz_offset


def gen_window_outer_dims(platform, dpr):
	"""Generates random but plausible window.outer dimensions based on platform."""
	is_mobile = platform in ['Android', 'iOS']

	if is_mobile:
		# Viewports from popular Samsung and Apple phones.
		mobile_viewports = [
			# Samsung
			{'width': 1440, 'height': 2960}, {'width': 1440, 'height': 3040}, {'width': 1440, 'height': 3200},
			{'width': 1080, 'height': 2400}, {'width': 1080, 'height': 2340}, {'width': 1440, 'height': 3088},
			{'width': 1440, 'height': 3120},
			# Apple
			{'width': 750, 'height': 1334}, {'width': 1080, 'height': 1920}, {'width': 1125, 'height': 2436},
			{'width': 1242, 'height': 2688}, {'width': 828, 'height': 1792}, {'width': 1170, 'height': 2532},
			{'width': 1284, 'height': 2778}, {'width': 1290, 'height': 2796}, {'width': 1179, 'height': 2556}
		]

		selected_viewport = random.choice(mobile_viewports)
		width = selected_viewport['width']
		height = selected_viewport['height']

		# Adjust for status bar, etc.
		height -= random.randint(100, 150)

		# 10% chance for landscape orientation
		if random.random() < 0.1:
			# also subtract width on landscape
			width -= random.randint(100, 150)

			width, height = height, width

		# Per user feedback, divide physical resolution by DPR to get logical pixels
		width = round(width / dpr)
		height = round(height / dpr)

		return {'ww': width, 'wh': height}

	# ignore devicePixelRatio here, firefox fakes as 2
	
	# Generate a landscape-like aspect ratio (e.g., between 1:1 and 16:9)
	ratio = 1 + random.random() * (16/9 - 1) # Ratio: 1.0 to ~1.778
	width = random.randint(1280, 2560 - 100) # Width: 1280 to 2560
	height = round(width / ratio)

	# Adjust for title bar
	height -= random.randint(60, 100)

	return {'ww': width, 'wh': height}

g_script_load_time = int(time.time())
g_session_cft = None

def _generate_integrity(ip, tz, browser, platform, target_url):
	"""Generates a new fingerprint object."""
	global g_session_cft
	
	is_chrome = browser in ['chrome', 'edge'] and platform != 'iOS'
	is_gecko = browser in ['firefox', 'tor'] and platform != 'iOS'
	is_safari_webkit = browser == 'safari' or platform == 'iOS'
	is_desktop_webkit = is_safari_webkit and platform == 'Mac'

	dpr = random.randint(2, 4) if platform in ['Android', 'iOS'] else random.randint(1, 2)
	viewport = gen_window_outer_dims(platform, dpr)
	
	# x86 platforms should have arch: 255, the rest 127?
	arch_value = 255 if platform in ['Windows', 'Linux'] else 127

	fp = {
		"ap": random.randint(0, 1) if is_safari_webkit else 0,
		"arch": arch_value,
		"cd": 24,
		"dpr": dpr,
		"dm": 0 if is_gecko else random.choice([2, 4, 8]),
		"hc": random.choice([2, 4, 6, 8, 12, 16, 24, 32]),
		"ww": viewport['ww'],
		"wh": viewport['wh'],
		"tz": tz,
		"rn": random.randint(-0x80000000, 0x7FFFFFFF),
		"ti": ip,
		"tei": ip,
		"uhd": 0,
		"uhblwc": 0,
		"tfvce": 0,
		"tfvw": 0,
		"ts": 0,
		"istr": 0,
		"iseh": 0,
		"isc": 1 if is_chrome else 0,
		"isdwk": 1 if is_desktop_webkit else 0,
		"isswk": 1 if is_safari_webkit else 0,
		"isg": 1 if is_gecko else 0,
		"isc86": 1,
		"isw606": 1,
		"pdc": random.randint(0, 1),
		"lsf": [random.randint(-0x80000000, 0x7FFFFFFF) for _ in range(4)],
		"cf": [random.randint(-0x80000000, 0x7FFFFFFF) for _ in range(4)],
		"cft": 0,
		"inc": 0,
		"lan": random.choice(["en-US", "en-US,en"]),
		"loc": "en-US",
		"ur": get_unmasked_renderer(platform, is_gecko),
		"np": "Linux" if platform == "Android" else platform, # android has "Linux armv81"
		"url": target_url,
		"ss": "None selected",
		"tt": 0,
		"plt": 0,
		"f": 0,
		"v": 20
	}

	now = int(time.time() * 1000)
	min_cft = 20
	max_cft = 1000
	min_tt = 10
	max_tt = 200

	if REUSE_FINGERPRINT:
		if not g_session_cft:
			g_session_cft = random.randint(min_cft, max_cft)
			fp["tt"] = g_session_cft + random.randint(min_tt, max_tt)
		else:
			fp["tt"] = random.randint(min_tt, max_tt)
		fp["cft"] = g_session_cft

		fp["ts"] = int((now - fp["tt"]) / 1000)

		fp["plt"] = g_script_load_time
	else:
		fp["cft"] = random.randint(min_cft, max_cft)
		fp["tt"] = fp["cft"] + random.randint(min_tt, max_tt)

		fp["ts"] = int((now - fp["tt"]) / 1000)
		
		# make plt a random time from pageload to now
		fp["plt"] = random.randint(g_script_load_time, fp["ts"])

	return fp

def get_spoofed_integrity(browser, platform, target_url, browser_version, os_version, request_args=None):
	if request_args is None:
		request_args = {}
		
	ip = get_public_ip(request_args)
	stored_entries = load_entries()

	try:
		entry_index = next(i for i, entry in enumerate(stored_entries) if entry.get('ip') == ip)
		entry_to_use = stored_entries[entry_index]
	except StopIteration:
		entry_index = -1
		entry_to_use = None

	final_fp = None

	# Check if a full fingerprint exists and reuse is enabled
	if REUSE_FINGERPRINT and entry_to_use and 'fingerprint' in entry_to_use:
		print("IP matched. Reusing stored fingerprint with updated dynamic values")
		
		# dummy None for time zone as its not needed
		current_fp = _generate_integrity(ip, None, browser, platform, target_url)

		# Update dynamic properties
		entry_to_use['fingerprint']['rn'] = current_fp['rn']
		entry_to_use['fingerprint']['plt'] = current_fp['plt']
		entry_to_use['fingerprint']['ts'] = current_fp['ts']
		entry_to_use['fingerprint']['cft'] = current_fp['cft']
		entry_to_use['fingerprint']['tt'] = current_fp['tt']
		entry_to_use['fingerprint']['url'] = current_fp['url']
		entry_to_use['last_used'] = int(time.time() * 1000)
		
		final_fp = entry_to_use['fingerprint']
		stored_entries[entry_index] = entry_to_use

	else:
		if REUSE_FINGERPRINT:
			print("No IP matching fingerprint found. Generating and storing a new one")
		else:
			print("Fingerprint reuse is disabled. Generating a new one for this session")

		tz = None
		# Check for a stored time zone, even in a partial entry
		if entry_to_use and 'fingerprint' in entry_to_use and 'tz' in entry_to_use.get('fingerprint', {}):
			print(f"Found stored time zone for IP {ip}. Reusing it")
			tz = entry_to_use['fingerprint']['tz']
		else:
			print(f"No stored time zone for IP {ip}. Fetching new one")
			tz = get_timezone_for_ip(ip, request_args)

		new_fp = _generate_integrity(ip, tz, browser, platform, target_url)
		final_fp = new_fp
		
		if entry_to_use:
			# Update the partial entry with the new fingerprint
			entry_to_use['fingerprint'] = new_fp
			entry_to_use['last_used'] = int(time.time() * 1000)
			entry_to_use['browser'] = browser
			entry_to_use['platform'] = platform
			entry_to_use['browser_version'] = browser_version
			entry_to_use['os_version'] = os_version
			stored_entries[entry_index] = entry_to_use
		else:
			# Create a completely new entry
			new_entry = {
				'ip': ip,
				'fingerprint': new_fp, 
				'last_used': int(time.time() * 1000),
				'browser': browser,
				'platform': platform,
				'browser_version': browser_version,
				'os_version': os_version
			}
			stored_entries.append(new_entry)

		if len(stored_entries) > CACHE_SIZE:
			stored_entries.sort(key=lambda x: x['last_used'], reverse=True)
			stored_entries = stored_entries[:CACHE_SIZE]

	save_entries(stored_entries)
	
	return final_fp


def xorshift32(state):
	"""Replicates the xorshift32 PRNG from the userscript."""
	x = state[0]
	x ^= (x << 13) & 0xFFFFFFFF
	x ^= x >> 17
	x ^= (x << 5) & 0xFFFFFFFF
	state[0] = x
	return x

def gen_prng_bytes(num_bytes, seed):
	"""Generates a byte array using the xorshift32 PRNG."""
	state = [seed]
	return bytes([(xorshift32(state) & 0xFF) for _ in range(num_bytes)])

AES_KEY = bytes.fromhex("2F 20 43 6A C0 52 69 21 1A 50 DD E4 2E D5 B4 A1")

def encrypt_integrity(integrity_obj):
	"""Encrypts the integrity object into the final payload."""
	plaintext = json.dumps(integrity_obj, separators=(',', ':')).encode('utf-8')
	
	# Null-byte padding
	padding_amount = 16 - (len(plaintext) % 16)
	padded_plaintext = plaintext + (b'\x00' * padding_amount)
	
	# IV generation from timestamp
	iv_seed = integrity_obj['ts']
	iv = gen_prng_bytes(16, iv_seed)
	
	cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
	encrypted_data = cipher.encrypt(padded_plaintext)
	
	result = {
		"iv": base64.b64encode(iv).decode('utf-8'),
		"data": base64.b64encode(encrypted_data).decode('utf-8')
	}
	
	return json.dumps(result)


PRICK_CACHE_DURATION = 15 * 60  # 15 minutes in seconds

def get_prick(request_args=None):
	"""
	Fetches the prick value, using a cache to avoid repeated requests.
	The cache is only used if the current public IP matches the one stored.
	"""
	if request_args is None:
		request_args = {}
	current_ip = get_public_ip(request_args)
	entries = load_entries()
	
	try:
		entry_index = next(i for i, entry in enumerate(entries) if entry.get('ip') == current_ip)
		cached_entry = entries[entry_index]
	except StopIteration:
		entry_index = -1
		cached_entry = None

	# Check if prick is valid in the found entry
	if cached_entry and 'prick' in cached_entry and time.time() - (cached_entry.get('prick_timestamp', 0) / 1000) < PRICK_CACHE_DURATION:
		print("Using cached prick value")
		return cached_entry['prick']

	# Fetch new prick value
	print("Fetching new prick value...")
	try:
		response = requests.get("https://4.prick.soyjak.st/", **request_args)
		response.raise_for_status()
		prick_value = response.text
		
		# Update cache
		if cached_entry:
			# Update existing entry for this IP
			cached_entry['prick'] = prick_value
			cached_entry['prick_timestamp'] = int(time.time() * 1000)
		else:
			# Create a new partial entry just for the IP and prick.
			# The full fingerprint will be added by get_spoofed_integrity.
			new_entry = {
				'ip': current_ip,
				'prick': prick_value,
				'prick_timestamp': int(time.time() * 1000),
				'last_used': int(time.time() * 1000)
			}
			entries.append(new_entry)

		save_entries(entries)
			
		return prick_value
	except requests.errors.RequestsError as e:
		print(f"Failed to fetch prick value: {e}")
		return None

def generate_password(length=random.randint(8, 17)):
	characters = string.ascii_letters + string.digits + string.punctuation
	return ''.join(random.choice(characters) for i in range(length))

def post_to_soyjak(target_url, proxy, browser, platform, use_impersonate=True, 
	post_comment=None, subject=None, email=None,
	file_paths=None, randomize_filename=True, change_hash=True,
	browser_version=None, os_version=None):

	thread_match = re.search(r'^https?://soyjak\.st/([^/]+)/thread/(\d+)', target_url)
	board_match = re.search(r'^https?://soyjak\.st/([^/]+)/(?:catalog\.html|index\.html$|$)', target_url)

	if thread_match:
		board = thread_match.group(1)
		thread_id = thread_match.group(2)
		print(f"Replying to thread {thread_id} on board /{board}/")
	elif board_match:
		board = board_match.group(1)
		thread_id = '' 
		print(f"Creating new thread on board /{board}/")
	else:
		print("Error: Could not extract board and thread ID from URL")
		print("Example valid URL formats: https://soyjak.st/soy/thread/12345.html, https://soyjak.st/qa/, https://soyjak.st/pol/index.html, https://soyjak.st/soy/catalog.html")
		return

	request_args = get_default_request_args(proxy)

	if REUSE_FINGERPRINT:
		ip_for_cache_check = get_public_ip(request_args)
		stored_entries = load_entries()
		
		try:
			entry_for_ip = next(entry for entry in stored_entries if entry['ip'] == ip_for_cache_check)
			cached_browser = entry_for_ip.get('browser')
			cached_platform = entry_for_ip.get('platform')
			cached_browser_version = entry_for_ip.get('browser_version')
			cached_os_version = entry_for_ip.get('os_version')

			if cached_browser and cached_platform:
				print(f"Switching to cached browser/platform for fingerprint: {cached_browser}/{cached_platform}")
				browser = cached_browser
				platform = cached_platform
				browser_version = cached_browser_version
				os_version = cached_os_version
		except (StopIteration, KeyError):
			pass # No entry for this IP, or entry is partial. Proceed with given browser/platform
	
	min_versions = {
		BrowserTypes.CHROME: 137,
		BrowserTypes.EDGE: 137,
		BrowserTypes.FIREFOX: 120,
		BrowserTypes.TOR: 120,
		BrowserTypes.SAFARI: 13,
		PlatformTypes.ANDROID: 10
	}

	config = get_browser_config(browser, platform, use_impersonate=use_impersonate,
		browser_version=browser_version, os_version=os_version, min_versions=min_versions)

	fp_info_msg = f"Using platform: {config['platform']}, browser: {config['browser']} v{config.get('browser_version', 'N/A')}"
	os_version = config.get('os_version')
	if os_version:
		fp_info_msg += f", OS v{os_version}"

	if use_impersonate:
		fp_info_msg += f", impersonate: {config['impersonate']}"

	print(fp_info_msg)

	if use_impersonate:
		request_args["impersonate"] = config['impersonate']
	else:
		request_args["akamai"] = config['akamai_fp']
		request_args["ja3"] = config['ja3']
		request_args["extra_fp"] = config['extra_fp']

	with HeaderAwareSession(config, use_impersonate=use_impersonate, **request_args) as s:
		if random.random() < 0.5:
			print("Adding serv cookie...")
			s.cookies.set("serv", "{}", domain="soyjak.st", path="/")

		print("Opening target URL...")
		response = s.get(target_url)
		response.raise_for_status()
		print("Target URL opened successfully! Status code:", response.status_code)

		prick_value = get_prick(request_args)
		if not prick_value:
			print(f"Failed to fetch prick value, aborting")
			return

		print(f"Getting integrity for '{config['browser']}' on '{config['platform']}'...")
		integrity = get_spoofed_integrity(config['browser'], config['platform'], target_url, config['browser_version'], config['os_version'], request_args=request_args)
		integrity_encrypted = encrypt_integrity(integrity)

		form_data = [
			('board', board),
			('email', email or ''),
			('subject', subject or ''),
			('body', post_comment or ''),
			('captcha_text', ''),
			('x', ''), # captcha X
			('y', ''), # captcha Y
			('guid', ''), # captcha guid d62ab25c-1b9e-4cae-b129-f74de1f3f92a
			('embed', ''),
			('password', generate_password()),
			('hash', ''),
			('json_response', '1'),
			('post', 'Post'),
			('prick-4', prick_value),
			('integrity-v2', integrity_encrypted)
		]

		if thread_id:
			form_data.insert(0, ('thread', thread_id))

		if file_paths:
			for form_name, file_path in file_paths.items():
				if not file_path:
					continue

				filename_to_use = os.path.basename(file_path)
				if randomize_filename:
					now = time.time()
					random_timestamp_float = random.uniform(now - 31536000, now)
					_, extension = os.path.splitext(file_path)
					filename_to_use = f"{int(random_timestamp_float * 1000)}{extension}"

				try:
					with open(file_path, 'rb') as f:
						file_content = f.read()
				except FileNotFoundError:
					print(f"Error: File not found at {file_path}")
					sys.exit(1)
				except Exception as e:
					print(f"Error reading file {file_path}: {e}")
					sys.exit(1)

				content_type, _ = mimetypes.guess_type(filename_to_use)
				if not content_type:
					content_type = 'application/octet-stream'

				if change_hash:
					file_content = change_file_hash(file_content, content_type)
				
				file_payload = {
					'filename': filename_to_use,
					'content': file_content,
					'content_type': content_type
				}
				form_data.append((form_name, file_payload))

		print("Sending post request...")
		response = s.post(
			"https://soyjak.st/post.php",
			multipart=form_data,
			referer=target_url
		)

	response.raise_for_status()
	print("Post request sent successfully! Status code:", response.status_code)
	try:
		print("Post request response JSON:", response.json())
	except json.JSONDecodeError:
		print("Post request response content:", response.text)

def main(args):
	"""
	Main function to handle posting logic. Can be called from other scripts.
	"""
	if hasattr(args, 'debug') and args.debug:
		print("--- Running in Debug Mode ---")
		request_args = get_default_request_args(args.proxy)
		debug_fingerprint(
			browser=args.browser,
			platform=args.platform,
			request_args=request_args,
			use_impersonate=not args.no_impersonate,
			browser_version=args.browser_version,
			os_version=args.os_version
		)
		return

	# Safe access to attributes for programmatic calls
	file = getattr(args, 'file', None)
	file2 = getattr(args, 'file2', None)
	file3 = getattr(args, 'file3', None)
	file4 = getattr(args, 'file4', None)
	comment = getattr(args, 'comment', None)
	comment_from_file = getattr(args, 'comment_from_file', None)
	bypass_banned_text = getattr(args, 'bypass_banned_text', False)

	if not any([file, file2, file3, file4, comment, comment_from_file]):
		raise ValueError("At least one file or comment is required")

	if bypass_banned_text and not (comment or comment_from_file):
		raise ValueError("--bypass-banned-text can only be used with --comment or --comment-from-file")

	post_comment = None
	if comment:
		post_comment = codecs.escape_decode(comment)[0].decode('utf-8')
	elif comment_from_file:
		try:
			with open(comment_from_file, 'r', encoding='utf-8') as f:
				post_comment = f.read()
		except FileNotFoundError:
			raise FileNotFoundError(f"Error: Comment file not found at {comment_from_file}")
		except Exception as e:
			raise IOError(f"Error reading comment file: {e}")

	if bypass_banned_text and post_comment:
		post_comment = insert_zero_width_char_in_each_word(post_comment)

	file_paths = {
		"file": file,
		"file2": file2,
		"file3": file3,
		"file4": file4,
	}

	post_to_soyjak(
		args.target_url,
		getattr(args, 'proxy', None),
		getattr(args, 'browser', None),
		getattr(args, 'platform', None),
		use_impersonate=not getattr(args, 'no_impersonate', False),
		post_comment=post_comment,
		subject=getattr(args, 'subject', None),
		email=getattr(args, 'email', None),
		file_paths=file_paths,
		randomize_filename=not getattr(args, 'no_random_filename', False),
		change_hash=not getattr(args, 'no_hash_change', False),
		browser_version=getattr(args, 'browser_version', None),
		os_version=getattr(args, 'os_version', None)
	)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Post to soyjak.st with a specified browser fingerprint")

	parser.add_argument("target_url", help="The URL of the thread to post in")
	parser.add_argument("--proxy", nargs='?', default="socks5h://127.0.0.1:1080", const=None,
		help="The proxy to use for requests. If flag is present with no value, no proxy is used. Defaults to 'socks5h://127.0.0.1:1080'")
	parser.add_argument("--browser", type=BrowserTypes.from_str, help="The browser to emulate. Random if not specified")
	parser.add_argument("--platform", type=PlatformTypes.from_str, help="The OS platform to emulate. Random if not specified")
	parser.add_argument("--no-impersonate", action="store_true", help="Do not use fingerprints built into curl_cffi")
	comment_group = parser.add_mutually_exclusive_group()
	comment_group.add_argument("--comment", help="The comment for the post, supports escape sequences")
	comment_group.add_argument("--comment-from-file", help="Path to a file containing the comment for the post")
	parser.add_argument("--bypass-banned-text", action="store_true", help="Insert a random zero-width space in each word of the comment")
	parser.add_argument("--subject", help="The subject for the post")
	parser.add_argument("--email", help="The email for the post")
	parser.add_argument("--file", help="Path to the file to upload")
	parser.add_argument("--file2", help="Path to the second file to upload")
	parser.add_argument("--file3", help="Path to the third file to upload")
	parser.add_argument("--file4", help="Path to the fourth file to upload")
	parser.add_argument("--no-random-filename", action="store_true", help="Do not randomize the filename before uploading")
	parser.add_argument("--no-hash-change", action="store_true", help="Do not change the file hash before uploading")
	parser.add_argument("--browser-version", type=int, help="The major browser version to emulate (e.g., 144)")
	parser.add_argument("--os-version", type=int, help="The major OS version to emulate (e.g., 17 for iOS, 14 for Android)")
	parser.add_argument("--debug", action="store_true", help="Fetch TLS test pages instead of posting to debug the fingerprint")
	args = parser.parse_args()

	try:
		main(args)
	except (ValueError, FileNotFoundError, IOError) as e:
		print(f"Error: {e}", file=sys.stderr)
		sys.exit(1)
	except Exception as e:
		print(f"An unexpected error occurred: {e}", file=sys.stderr)
		sys.exit(1)
