(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
/*!
 * Aprico-gen
 * Deterministic password generator library based on scrypt algorithm. 
 * Copyright (c) 2018 Pino Ceniccola | GPLv3
 * https://aprico.org
 */

const aprico = (()=> {
	'use strict';

	const scrypt = (typeof module !== 'undefined' && module.exports) ? require('scrypt-async') : window.scrypt;

	if (typeof scrypt !== 'function')
		throw new Error("Aprico requires scrypt-async-js library.");

	const VERSION = "1.0.0";

	const SCRYPT_COST = {
    	N: Math.pow(2,14),
    	r: 8,
    	p: 1,
    	dkLen: 32,
    	encoding: 'hex'
	};

	const SCRYPT_COST_FAST = {
    	N: Math.pow(2,5),
    	r: 8,
    	p: 1,
    	dkLen: 32,
    	encoding: 'hex'
	};

	const ALPHABET = {
		letters : 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ',
		numbers : '123456789',
		symbols : '_!$-+'
	};

	let options = {
		length : 20,
		letters : true,
		numbers : true,
		symbols	: true,
		variant : false
	};


	/**
	* Arbitrary conversion from one character set to another,
	* using Base 10 as an intermediate base for conversion.
	* Used by _hashToAlphabet().
	* (Adapted from: https://rot47.net/base.html)
	*
	* @param {string} src 	  	String to convert
	* @param {string} srctable	Source character set
	* @param {string} srcdest	Destination character set
	*
	* @returns {string} 	   	Converted string
	*/
	const _convert = (src, srctable, desttable) => {
		const srclen = srctable.length;
		const destlen = desttable.length;
		// Convert to base 10
		let val = 0;
		for (let i=0, numlen = src.length; i<numlen; i++) {
			val = val * srclen + srctable.indexOf(src.charAt(i));
		};
		if (val<0) {return 0;}
		// Then convert to destination base
		let r = val % destlen;
		let res = desttable.charAt(r);
		let q = Math.floor(val/destlen);
		while (q) {
			r = q % destlen;
			q = Math.floor(q/destlen);
			res = desttable.charAt(r) + res;
		}
		return res;
	};


	/**
	 * Convert full hex hash to password format
	 * set by options (alphabet and length)
	 *
	 * @param   {string} hash 	Hash in hex format
	 *
	 * @returns {string} 		The generated password
	 */
	const _hashToAlphabet = (hash) => {
		let alphabet = '';
		if (options.symbols) alphabet += ALPHABET.symbols;
		if (options.numbers) alphabet += ALPHABET.numbers;
		if (options.letters) alphabet += ALPHABET.letters;

		let result = '';

		// We split the full hash because... 32bit
		let split = hash.match(/(.{1,7})/g);
		for (let i = 0, l = split.length-1; i < l; i++) {

    		//[debug] console.log('Split', split);

    		// Re-hash every slice when revealing a potentially
    		// large chunk of the original hash.
    		if (options.length > 9) {

    			//[debug] console.log('Re-hashing', hash, split[l-i-1]);

    			scrypt (hash, split[l-i-1], SCRYPT_COST_FAST, function(hash){
    				split = hash.match(/(.{1,7})/g);
    			});
    		}

    		result += _convert(split[i], '0123456789abcdef', alphabet);

		};

		//[debug] console.log('Full converted string', result);

		// Better safe than sorry
		if (result.length<=options.length) return ".";

		// Trim password to options.length
		let offset = ((result.length-options.length)/2)|0;

		//[debug] console.log('Trim offset', offset);

		result = result.substring(offset, offset + options.length);

		// Make sure first character is [A-z]
		// because... silly password rules
		let firstChar = result.charAt(0);
		if (options.letters && options.length > 6 && !/[a-zA-Z]/.test(firstChar)) {

			//[debug] console.log('First character to be replaced', result);

			result = result.replace(firstChar, _convert(firstChar, ALPHABET.symbols+ALPHABET.numbers, ALPHABET.letters));
		}

		return result;
	};


	/**
	 * Check if the generated password has characters from
	 * every alphabet set. If not, re-hash until conditions are met.
	 *
	 * @param   {object} results	Password + Hash
	 *
	 * @returns {object} 			Password + Hash
	 */
	const _checkAndIterate = (results) => {

		let success = false;

		while (!success) {

			success = true;

			// Check for...
			// 1. at least one uppercase, one lowecase letter, no letter repeated three times (eg. aaa)
			if ( options.letters && ( !/[a-z]/.test(results.pass) || !/[A-Z]/.test(results.pass) || /([A-z])\1{2}/.test(results.pass) ) ) success = false;

			// 2. at least one number and no number repeated three times (eg. 111)
			if ( success && options.numbers && ( !/[\d]/.test(results.pass) || /([\d])\1{2}/.test(results.pass) ) ) success = false;

			// 3. at least one symbol and no symbol repeated three times (eg. $$$)
			if ( success && options.symbols && ( !/[!$\-+_]/.test(results.pass) || /([!$\-+_])\1{2}/.test(results.pass) ) ) success = false;


			if (!success) {

				//[debug] console.log('Iterating', results);

				// Re-hash until conditions are met.
				scrypt (results.hash, results.pass, SCRYPT_COST_FAST, function(hash){

					results.hash = hash;
					results.pass = _hashToAlphabet(hash);

				});

			}

		}

		return results;

	};


	/**
	 * Merge and check user options.
	 *
	 * @param   {object} user_options	User options
	 */
	const _checkOptions = (user_options) => {

		for (let opt in options)
			if (user_options.hasOwnProperty(opt))
				options[opt] = user_options[opt];

		options.letters = !!options.letters;
		options.numbers = !!options.numbers;
		options.symbols = !!options.symbols;

		if (!options.letters && !options.symbols && !options.numbers)
			throw new Error("At least one character set (letters, numbers, symbols) must be chosen.");

		options.length = +options.length;

		if (typeof options.length !== 'number' || options.length < 4 || options.length > 40)
			throw new Error("Password length must be a number between 4 and 40.");

	};


	/**
	 * Deterministic password generation main function.
	 *
	 * @param   {string} password		User Master Password
	 * @param   {string} service		User service/domain
	 * @param   {string} hashId			Precomputed hash ID
	 * @param   {object} user_options	User options
	 *
	 * @returns {object} 				Password + Hash
	 */
	const getPassword = (password, service, hashId, user_options) => {

		if (user_options) _checkOptions(user_options);

		service = normalizeService(service);

		let pass = password + '.' + service + '.' + options.length + (+options.letters) + (+options.symbols) + (+options.numbers);

		if (options.variant && typeof options.variant === 'string') pass += '.' + options.variant;

		//[debug] console.log('String to hash', pass);

		let results = {};

		scrypt (pass, hashId, SCRYPT_COST, function(hash){

			results.hash = hash;
			results.pass = _hashToAlphabet(hash);

			results = _checkAndIterate(results);

		});
		
		//[debug] console.log('Results', results);
		
		return results;
		
	};



	/**
	 * Generate an hash from the user ID.
	 *
	 * @param   {string} id 	User ID
	 *
	 * @returns {string} 		Hash ID
	 */
	const getHashId = (id) => {
		let output = '';

		// In order to create an hash from the ID using scrypt,
		// we need to generate some deterministic salt and it's
		// not a bad thing.
		// Rationale: ID is a salt. It's not a secret.
		// We are not hashing a password.
		// We are converting ID to an hash more for convenience 
		// than security here.
		let salt = Math.pow(id.length, (id.match(/[aeiou]/gi) || [0,0,0]).length)+'';
		salt = _convert(salt, '0123456789.e+Infity', ALPHABET.numbers+ALPHABET.symbols+ALPHABET.letters)+'';

		//[debug] console.log('Hash ID salt',salt);

		scrypt(id, salt, SCRYPT_COST, function(hash) {
			output = hash;
		});

		return output;
	};


	/**
	 * If Service is a URL, it is stripped down to hostname (and
	 * perhaps port number) to improve usability.
	 *
	 * @param   {string} service 	User Service
	 *
	 * @returns {string} 			Normalized Service
	 */
	const normalizeService = (service) => {

		service = service.trim().toLowerCase();

		// Strip http(s)://
		if (service.substring(0, 4) == 'http') {
			service = service.substring(service.indexOf('://')+3, service.length);
		}

		// if string contains any "/" take only the first part
		if (service.indexOf('.') !== -1 && service.indexOf('/') !== -1) {
			service = service.split('/');
			service = service[0];
		}

		//[debug] console.log('Normalized Service', service);

		return service;
	};


	return {
		getPassword : getPassword,
		getHashId : getHashId,
		normalizeService : normalizeService,
		version : VERSION
	};

})();


if (typeof module !== 'undefined' && module.exports) {
	module.exports = aprico;
} else {
	window.aprico = aprico;
}
},{"scrypt-async":6}],2:[function(require,module,exports){

},{}],3:[function(require,module,exports){
(function (Buffer){
/**
 * Identicon.js 2.3.3
 * http://github.com/stewartlord/identicon.js
 *
 * PNGLib required for PNG output
 * http://www.xarg.org/download/pnglib.js
 *
 * Copyright 2018, Stewart Lord
 * Released under the BSD license
 * http://www.opensource.org/licenses/bsd-license.php
 */

(function() {
    var PNGlib;
    if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
        PNGlib = require('./pnglib');
    } else {
        PNGlib = window.PNGlib;
    }

    var Identicon = function(hash, options){
        if (typeof(hash) !== 'string' || hash.length < 15) {
            throw 'A hash of at least 15 characters is required.';
        }

        this.defaults = {
            background: [240, 240, 240, 255],
            margin:     0.08,
            size:       64,
            saturation: 0.7,
            brightness: 0.5,
            format:     'png'
        };

        this.options = typeof(options) === 'object' ? options : this.defaults;

        // backward compatibility with old constructor (hash, size, margin)
        if (typeof(arguments[1]) === 'number') { this.options.size   = arguments[1]; }
        if (arguments[2])                      { this.options.margin = arguments[2]; }

        this.hash        = hash
        this.background  = this.options.background || this.defaults.background;
        this.size        = this.options.size       || this.defaults.size;
        this.format      = this.options.format     || this.defaults.format;
        this.margin      = this.options.margin !== undefined ? this.options.margin : this.defaults.margin;

        // foreground defaults to last 7 chars as hue at 70% saturation, 50% brightness
        var hue          = parseInt(this.hash.substr(-7), 16) / 0xfffffff;
        var saturation   = this.options.saturation || this.defaults.saturation;
        var brightness   = this.options.brightness || this.defaults.brightness;
        this.foreground  = this.options.foreground || this.hsl2rgb(hue, saturation, brightness);
    };

    Identicon.prototype = {
        background: null,
        foreground: null,
        hash:       null,
        margin:     null,
        size:       null,
        format:     null,

        image: function(){
            return this.isSvg()
                ? new Svg(this.size, this.foreground, this.background)
                : new PNGlib(this.size, this.size, 256);
        },

        render: function(){
            var image      = this.image(),
                size       = this.size,
                baseMargin = Math.floor(size * this.margin),
                cell       = Math.floor((size - (baseMargin * 2)) / 5),
                margin     = Math.floor((size - cell * 5) / 2),
                bg         = image.color.apply(image, this.background),
                fg         = image.color.apply(image, this.foreground);

            // the first 15 characters of the hash control the pixels (even/odd)
            // they are drawn down the middle first, then mirrored outwards
            var i, color;
            for (i = 0; i < 15; i++) {
                color = parseInt(this.hash.charAt(i), 16) % 2 ? bg : fg;
                if (i < 5) {
                    this.rectangle(2 * cell + margin, i * cell + margin, cell, cell, color, image);
                } else if (i < 10) {
                    this.rectangle(1 * cell + margin, (i - 5) * cell + margin, cell, cell, color, image);
                    this.rectangle(3 * cell + margin, (i - 5) * cell + margin, cell, cell, color, image);
                } else if (i < 15) {
                    this.rectangle(0 * cell + margin, (i - 10) * cell + margin, cell, cell, color, image);
                    this.rectangle(4 * cell + margin, (i - 10) * cell + margin, cell, cell, color, image);
                }
            }

            return image;
        },

        rectangle: function(x, y, w, h, color, image){
            if (this.isSvg()) {
                image.rectangles.push({x: x, y: y, w: w, h: h, color: color});
            } else {
                var i, j;
                for (i = x; i < x + w; i++) {
                    for (j = y; j < y + h; j++) {
                        image.buffer[image.index(i, j)] = color;
                    }
                }
            }
        },

        // adapted from: https://gist.github.com/aemkei/1325937
        hsl2rgb: function(h, s, b){
            h *= 6;
            s = [
                b += s *= b < .5 ? b : 1 - b,
                b - h % 1 * s * 2,
                b -= s *= 2,
                b,
                b + h % 1 * s,
                b + s
            ];

            return[
                s[ ~~h    % 6 ] * 255, // red
                s[ (h|16) % 6 ] * 255, // green
                s[ (h|8)  % 6 ] * 255  // blue
            ];
        },

        toString: function(raw){
            // backward compatibility with old toString, default to base64
            if (raw) {
                return this.render().getDump();
            } else {
                return this.render().getBase64();
            }
        },

        isSvg: function(){
            return this.format.match(/svg/i)
        }
    };

    var Svg = function(size, foreground, background){
        this.size       = size;
        this.foreground = this.color.apply(this, foreground);
        this.background = this.color.apply(this, background);
        this.rectangles = [];
    };

    Svg.prototype = {
        size:       null,
        foreground: null,
        background: null,
        rectangles: null,

        color: function(r, g, b, a){
            var values = [r, g, b].map(Math.round);
            values.push((a >= 0) && (a <= 255) ? a/255 : 1);
            return 'rgba(' + values.join(',') + ')';
        },

        getDump: function(){
          var i,
                xml,
                rect,
                fg     = this.foreground,
                bg     = this.background,
                stroke = this.size * 0.005;

            xml = "<svg xmlns='http://www.w3.org/2000/svg'"
                + " width='" + this.size + "' height='" + this.size + "'"
                + " style='background-color:" + bg + ";'>"
                + "<g style='fill:" + fg + "; stroke:" + fg + "; stroke-width:" + stroke + ";'>";

            for (i = 0; i < this.rectangles.length; i++) {
                rect = this.rectangles[i];
                if (rect.color == bg) continue;
                xml += "<rect "
                    + " x='"      + rect.x + "'"
                    + " y='"      + rect.y + "'"
                    + " width='"  + rect.w + "'"
                    + " height='" + rect.h + "'"
                    + "/>";
            }
            xml += "</g></svg>"

            return xml;
        },

        getBase64: function(){
            if ('function' === typeof btoa) {
                return btoa(this.getDump());
            } else if (Buffer) {
                return new Buffer(this.getDump(), 'binary').toString('base64');
            } else {
                throw 'Cannot generate base64 output';
            }
        }
    };

    if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
        module.exports = Identicon;
    } else {
        window.Identicon = Identicon;
    }
})();

}).call(this,require("buffer").Buffer)
},{"./pnglib":4,"buffer":2}],4:[function(require,module,exports){
/**
* A handy class to calculate color values.
*
* @version 1.0
* @author Robert Eisele <robert@xarg.org>
* @copyright Copyright (c) 2010, Robert Eisele
* @link http://www.xarg.org/2010/03/generate-client-side-png-files-using-javascript/
* @license http://www.opensource.org/licenses/bsd-license.php BSD License
*
*/

(function() {

	// helper functions for that ctx
	function write(buffer, offs) {
		for (var i = 2; i < arguments.length; i++) {
			for (var j = 0; j < arguments[i].length; j++) {
				buffer[offs++] = arguments[i].charAt(j);
			}
		}
	}

	function byte2(w) {
		return String.fromCharCode((w >> 8) & 255, w & 255);
	}

	function byte4(w) {
		return String.fromCharCode((w >> 24) & 255, (w >> 16) & 255, (w >> 8) & 255, w & 255);
	}

	function byte2lsb(w) {
		return String.fromCharCode(w & 255, (w >> 8) & 255);
	}

	// modified from original source to support NPM
	var PNGlib = function(width,height,depth) {

		this.width   = width;
		this.height  = height;
		this.depth   = depth;

		// pixel data and row filter identifier size
		this.pix_size = height * (width + 1);

		// deflate header, pix_size, block headers, adler32 checksum
		this.data_size = 2 + this.pix_size + 5 * Math.floor((0xfffe + this.pix_size) / 0xffff) + 4;

		// offsets and sizes of Png chunks
		this.ihdr_offs = 0;									// IHDR offset and size
		this.ihdr_size = 4 + 4 + 13 + 4;
		this.plte_offs = this.ihdr_offs + this.ihdr_size;	// PLTE offset and size
		this.plte_size = 4 + 4 + 3 * depth + 4;
		this.trns_offs = this.plte_offs + this.plte_size;	// tRNS offset and size
		this.trns_size = 4 + 4 + depth + 4;
		this.idat_offs = this.trns_offs + this.trns_size;	// IDAT offset and size
		this.idat_size = 4 + 4 + this.data_size + 4;
		this.iend_offs = this.idat_offs + this.idat_size;	// IEND offset and size
		this.iend_size = 4 + 4 + 4;
		this.buffer_size  = this.iend_offs + this.iend_size;	// total PNG size

		this.buffer  = new Array();
		this.palette = new Object();
		this.pindex  = 0;

		var _crc32 = new Array();

		// initialize buffer with zero bytes
		for (var i = 0; i < this.buffer_size; i++) {
			this.buffer[i] = "\x00";
		}

		// initialize non-zero elements
		write(this.buffer, this.ihdr_offs, byte4(this.ihdr_size - 12), 'IHDR', byte4(width), byte4(height), "\x08\x03");
		write(this.buffer, this.plte_offs, byte4(this.plte_size - 12), 'PLTE');
		write(this.buffer, this.trns_offs, byte4(this.trns_size - 12), 'tRNS');
		write(this.buffer, this.idat_offs, byte4(this.idat_size - 12), 'IDAT');
		write(this.buffer, this.iend_offs, byte4(this.iend_size - 12), 'IEND');

		// initialize deflate header
		var header = ((8 + (7 << 4)) << 8) | (3 << 6);
		header+= 31 - (header % 31);

		write(this.buffer, this.idat_offs + 8, byte2(header));

		// initialize deflate block headers
		for (var i = 0; (i << 16) - 1 < this.pix_size; i++) {
			var size, bits;
			if (i + 0xffff < this.pix_size) {
				size = 0xffff;
				bits = "\x00";
			} else {
				size = this.pix_size - (i << 16) - i;
				bits = "\x01";
			}
			write(this.buffer, this.idat_offs + 8 + 2 + (i << 16) + (i << 2), bits, byte2lsb(size), byte2lsb(~size));
		}

		/* Create crc32 lookup table */
		for (var i = 0; i < 256; i++) {
			var c = i;
			for (var j = 0; j < 8; j++) {
				if (c & 1) {
					c = -306674912 ^ ((c >> 1) & 0x7fffffff);
				} else {
					c = (c >> 1) & 0x7fffffff;
				}
			}
			_crc32[i] = c;
		}

		// compute the index into a png for a given pixel
		this.index = function(x,y) {
			var i = y * (this.width + 1) + x + 1;
			var j = this.idat_offs + 8 + 2 + 5 * Math.floor((i / 0xffff) + 1) + i;
			return j;
		}

		// convert a color and build up the palette
		this.color = function(red, green, blue, alpha) {

			alpha = alpha >= 0 ? alpha : 255;
			var color = (((((alpha << 8) | red) << 8) | green) << 8) | blue;

			if (typeof this.palette[color] == "undefined") {
				if (this.pindex == this.depth) return "\x00";

				var ndx = this.plte_offs + 8 + 3 * this.pindex;

				this.buffer[ndx + 0] = String.fromCharCode(red);
				this.buffer[ndx + 1] = String.fromCharCode(green);
				this.buffer[ndx + 2] = String.fromCharCode(blue);
				this.buffer[this.trns_offs+8+this.pindex] = String.fromCharCode(alpha);

				this.palette[color] = String.fromCharCode(this.pindex++);
			}
			return this.palette[color];
		}

		// output a PNG string, Base64 encoded
		this.getBase64 = function() {

			var s = this.getDump();

			var ch = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
			var c1, c2, c3, e1, e2, e3, e4;
			var l = s.length;
			var i = 0;
			var r = "";

			do {
				c1 = s.charCodeAt(i);
				e1 = c1 >> 2;
				c2 = s.charCodeAt(i+1);
				e2 = ((c1 & 3) << 4) | (c2 >> 4);
				c3 = s.charCodeAt(i+2);
				if (l < i+2) { e3 = 64; } else { e3 = ((c2 & 0xf) << 2) | (c3 >> 6); }
				if (l < i+3) { e4 = 64; } else { e4 = c3 & 0x3f; }
				r+= ch.charAt(e1) + ch.charAt(e2) + ch.charAt(e3) + ch.charAt(e4);
			} while ((i+= 3) < l);
			return r;
		}

		// output a PNG string
		this.getDump = function() {

			// compute adler32 of output pixels + row filter bytes
			var BASE = 65521; /* largest prime smaller than 65536 */
			var NMAX = 5552;  /* NMAX is the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1 */
			var s1 = 1;
			var s2 = 0;
			var n = NMAX;

			for (var y = 0; y < this.height; y++) {
				for (var x = -1; x < this.width; x++) {
					s1+= this.buffer[this.index(x, y)].charCodeAt(0);
					s2+= s1;
					if ((n-= 1) == 0) {
						s1%= BASE;
						s2%= BASE;
						n = NMAX;
					}
				}
			}
			s1%= BASE;
			s2%= BASE;
			write(this.buffer, this.idat_offs + this.idat_size - 8, byte4((s2 << 16) | s1));

			// compute crc32 of the PNG chunks
			function crc32(png, offs, size) {
				var crc = -1;
				for (var i = 4; i < size-4; i += 1) {
					crc = _crc32[(crc ^ png[offs+i].charCodeAt(0)) & 0xff] ^ ((crc >> 8) & 0x00ffffff);
				}
				write(png, offs+size-4, byte4(crc ^ -1));
			}

			crc32(this.buffer, this.ihdr_offs, this.ihdr_size);
			crc32(this.buffer, this.plte_offs, this.plte_size);
			crc32(this.buffer, this.trns_offs, this.trns_size);
			crc32(this.buffer, this.idat_offs, this.idat_size);
			crc32(this.buffer, this.iend_offs, this.iend_size);

			// convert PNG to string
			return "\x89PNG\r\n\x1a\n"+this.buffer.join('');
		}
	}

	// modified from original source to support NPM
	if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
		module.exports = PNGlib;
	} else {
		window.PNGlib = PNGlib;
	}
})();

},{}],5:[function(require,module,exports){
// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;

process.listeners = function (name) { return [] }

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],6:[function(require,module,exports){
(function (setImmediate){
/*!
 * Fast "async" scrypt implementation in JavaScript.
 * Copyright (c) 2013-2016 Dmitry Chestnykh | BSD License
 * https://github.com/dchest/scrypt-async-js
 */

/**
 * scrypt(password, salt, options, callback)
 *
 * where
 *
 * password and salt are strings or arrays of bytes (Array of Uint8Array)
 * options is
 *
 * {
 *    N:      // CPU/memory cost parameter, must be power of two
 *            // (alternatively, you can specify logN)
 *    r:      // block size
 *    p:      // parallelization parameter
 *    dkLen:  // length of derived key, default = 32
 *    encoding: // optional encoding:
 *                    "base64" - standard Base64 encoding
 *                    "hex" — hex encoding,
 *                    "binary" — Uint8Array,
 *                    undefined/null - Array of bytes
 *    interruptStep: // optional, steps to split calculations (default is 0)
 * }
 *
 * Derives a key from password and salt and calls callback
 * with derived key as the only argument.
 *
 * Calculations are interrupted with setImmediate (or zero setTimeout) at the
 * given interruptSteps to avoid freezing the browser. If it's undefined or zero,
 * the callback is called immediately after the calculation, avoiding setImmediate.
 *
 * Legacy way (only supports p = 1) to call this function is:
 *
 * scrypt(password, salt, logN, r, dkLen, [interruptStep], callback, [encoding])
 *
 * In legacy API, if interruptStep is not given, it defaults to 1000.
 * Pass 0 to have callback called immediately.
 *
 */
function scrypt(password, salt, logN, r, dkLen, interruptStep, callback, encoding) {
  'use strict';

  function SHA256(m) {
    /** @const */ var K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
      0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
      0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
      0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
      0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
      0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
      0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
      0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
        h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19,
        w = new Array(64);

    function blocks(p) {
      var off = 0, len = p.length;
      while (len >= 64) {
        var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7,
            u, i, j, t1, t2;

        for (i = 0; i < 16; i++) {
          j = off + i*4;
          w[i] = ((p[j] & 0xff)<<24) | ((p[j+1] & 0xff)<<16) |
                 ((p[j+2] & 0xff)<<8) | (p[j+3] & 0xff);
        }

        for (i = 16; i < 64; i++) {
          u = w[i-2];
          t1 = ((u>>>17) | (u<<(32-17))) ^ ((u>>>19) | (u<<(32-19))) ^ (u>>>10);

          u = w[i-15];
          t2 = ((u>>>7) | (u<<(32-7))) ^ ((u>>>18) | (u<<(32-18))) ^ (u>>>3);

          w[i] = (((t1 + w[i-7]) | 0) + ((t2 + w[i-16]) | 0)) | 0;
        }

        for (i = 0; i < 64; i++) {
          t1 = ((((((e>>>6) | (e<<(32-6))) ^ ((e>>>11) | (e<<(32-11))) ^
               ((e>>>25) | (e<<(32-25)))) + ((e & f) ^ (~e & g))) | 0) +
               ((h + ((K[i] + w[i]) | 0)) | 0)) | 0;

          t2 = ((((a>>>2) | (a<<(32-2))) ^ ((a>>>13) | (a<<(32-13))) ^
               ((a>>>22) | (a<<(32-22)))) + ((a & b) ^ (a & c) ^ (b & c))) | 0;

          h = g;
          g = f;
          f = e;
          e = (d + t1) | 0;
          d = c;
          c = b;
          b = a;
          a = (t1 + t2) | 0;
        }

        h0 = (h0 + a) | 0;
        h1 = (h1 + b) | 0;
        h2 = (h2 + c) | 0;
        h3 = (h3 + d) | 0;
        h4 = (h4 + e) | 0;
        h5 = (h5 + f) | 0;
        h6 = (h6 + g) | 0;
        h7 = (h7 + h) | 0;

        off += 64;
        len -= 64;
      }
    }

    blocks(m);

    var i, bytesLeft = m.length % 64,
        bitLenHi = (m.length / 0x20000000) | 0,
        bitLenLo = m.length << 3,
        numZeros = (bytesLeft < 56) ? 56 : 120,
        p = m.slice(m.length - bytesLeft, m.length);

    p.push(0x80);
    for (i = bytesLeft + 1; i < numZeros; i++) p.push(0);
    p.push((bitLenHi>>>24) & 0xff);
    p.push((bitLenHi>>>16) & 0xff);
    p.push((bitLenHi>>>8)  & 0xff);
    p.push((bitLenHi>>>0)  & 0xff);
    p.push((bitLenLo>>>24) & 0xff);
    p.push((bitLenLo>>>16) & 0xff);
    p.push((bitLenLo>>>8)  & 0xff);
    p.push((bitLenLo>>>0)  & 0xff);

    blocks(p);

    return [
      (h0>>>24) & 0xff, (h0>>>16) & 0xff, (h0>>>8) & 0xff, (h0>>>0) & 0xff,
      (h1>>>24) & 0xff, (h1>>>16) & 0xff, (h1>>>8) & 0xff, (h1>>>0) & 0xff,
      (h2>>>24) & 0xff, (h2>>>16) & 0xff, (h2>>>8) & 0xff, (h2>>>0) & 0xff,
      (h3>>>24) & 0xff, (h3>>>16) & 0xff, (h3>>>8) & 0xff, (h3>>>0) & 0xff,
      (h4>>>24) & 0xff, (h4>>>16) & 0xff, (h4>>>8) & 0xff, (h4>>>0) & 0xff,
      (h5>>>24) & 0xff, (h5>>>16) & 0xff, (h5>>>8) & 0xff, (h5>>>0) & 0xff,
      (h6>>>24) & 0xff, (h6>>>16) & 0xff, (h6>>>8) & 0xff, (h6>>>0) & 0xff,
      (h7>>>24) & 0xff, (h7>>>16) & 0xff, (h7>>>8) & 0xff, (h7>>>0) & 0xff
    ];
  }

  function PBKDF2_HMAC_SHA256_OneIter(password, salt, dkLen) {
    // compress password if it's longer than hash block length
    if(password.length > 64) {
      // SHA256 expects password to be an Array. If it's not
      // (i.e. it doesn't have .push method), convert it to one.
      password = SHA256(password.push ? password : Array.prototype.slice.call(password, 0));
    }

    var i, innerLen = 64 + salt.length + 4,
        inner = new Array(innerLen),
        outerKey = new Array(64),
        dk = [];

    // inner = (password ^ ipad) || salt || counter
    for (i = 0; i < 64; i++) inner[i] = 0x36;
    for (i = 0; i < password.length; i++) inner[i] ^= password[i];
    for (i = 0; i < salt.length; i++) inner[64+i] = salt[i];
    for (i = innerLen - 4; i < innerLen; i++) inner[i] = 0;

    // outerKey = password ^ opad
    for (i = 0; i < 64; i++) outerKey[i] = 0x5c;
    for (i = 0; i < password.length; i++) outerKey[i] ^= password[i];

    // increments counter inside inner
    function incrementCounter() {
      for (var i = innerLen-1; i >= innerLen-4; i--) {
        inner[i]++;
        if (inner[i] <= 0xff) return;
        inner[i] = 0;
      }
    }

    // output blocks = SHA256(outerKey || SHA256(inner)) ...
    while (dkLen >= 32) {
      incrementCounter();
      dk = dk.concat(SHA256(outerKey.concat(SHA256(inner))));
      dkLen -= 32;
    }
    if (dkLen > 0) {
      incrementCounter();
      dk = dk.concat(SHA256(outerKey.concat(SHA256(inner))).slice(0, dkLen));
    }
    return dk;
  }

  function salsaXOR(tmp, B, bin, bout) {
    var j0  = tmp[0]  ^ B[bin++],
        j1  = tmp[1]  ^ B[bin++],
        j2  = tmp[2]  ^ B[bin++],
        j3  = tmp[3]  ^ B[bin++],
        j4  = tmp[4]  ^ B[bin++],
        j5  = tmp[5]  ^ B[bin++],
        j6  = tmp[6]  ^ B[bin++],
        j7  = tmp[7]  ^ B[bin++],
        j8  = tmp[8]  ^ B[bin++],
        j9  = tmp[9]  ^ B[bin++],
        j10 = tmp[10] ^ B[bin++],
        j11 = tmp[11] ^ B[bin++],
        j12 = tmp[12] ^ B[bin++],
        j13 = tmp[13] ^ B[bin++],
        j14 = tmp[14] ^ B[bin++],
        j15 = tmp[15] ^ B[bin++],
        u, i;

    var x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7,
        x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14,
        x15 = j15;

    for (i = 0; i < 8; i += 2) {
      u =  x0 + x12;   x4 ^= u<<7  | u>>>(32-7);
      u =  x4 +  x0;   x8 ^= u<<9  | u>>>(32-9);
      u =  x8 +  x4;  x12 ^= u<<13 | u>>>(32-13);
      u = x12 +  x8;   x0 ^= u<<18 | u>>>(32-18);

      u =  x5 +  x1;   x9 ^= u<<7  | u>>>(32-7);
      u =  x9 +  x5;  x13 ^= u<<9  | u>>>(32-9);
      u = x13 +  x9;   x1 ^= u<<13 | u>>>(32-13);
      u =  x1 + x13;   x5 ^= u<<18 | u>>>(32-18);

      u = x10 +  x6;  x14 ^= u<<7  | u>>>(32-7);
      u = x14 + x10;   x2 ^= u<<9  | u>>>(32-9);
      u =  x2 + x14;   x6 ^= u<<13 | u>>>(32-13);
      u =  x6 +  x2;  x10 ^= u<<18 | u>>>(32-18);

      u = x15 + x11;   x3 ^= u<<7  | u>>>(32-7);
      u =  x3 + x15;   x7 ^= u<<9  | u>>>(32-9);
      u =  x7 +  x3;  x11 ^= u<<13 | u>>>(32-13);
      u = x11 +  x7;  x15 ^= u<<18 | u>>>(32-18);

      u =  x0 +  x3;   x1 ^= u<<7  | u>>>(32-7);
      u =  x1 +  x0;   x2 ^= u<<9  | u>>>(32-9);
      u =  x2 +  x1;   x3 ^= u<<13 | u>>>(32-13);
      u =  x3 +  x2;   x0 ^= u<<18 | u>>>(32-18);

      u =  x5 +  x4;   x6 ^= u<<7  | u>>>(32-7);
      u =  x6 +  x5;   x7 ^= u<<9  | u>>>(32-9);
      u =  x7 +  x6;   x4 ^= u<<13 | u>>>(32-13);
      u =  x4 +  x7;   x5 ^= u<<18 | u>>>(32-18);

      u = x10 +  x9;  x11 ^= u<<7  | u>>>(32-7);
      u = x11 + x10;   x8 ^= u<<9  | u>>>(32-9);
      u =  x8 + x11;   x9 ^= u<<13 | u>>>(32-13);
      u =  x9 +  x8;  x10 ^= u<<18 | u>>>(32-18);

      u = x15 + x14;  x12 ^= u<<7  | u>>>(32-7);
      u = x12 + x15;  x13 ^= u<<9  | u>>>(32-9);
      u = x13 + x12;  x14 ^= u<<13 | u>>>(32-13);
      u = x14 + x13;  x15 ^= u<<18 | u>>>(32-18);
    }

    B[bout++] = tmp[0]  = (x0  + j0)  | 0;
    B[bout++] = tmp[1]  = (x1  + j1)  | 0;
    B[bout++] = tmp[2]  = (x2  + j2)  | 0;
    B[bout++] = tmp[3]  = (x3  + j3)  | 0;
    B[bout++] = tmp[4]  = (x4  + j4)  | 0;
    B[bout++] = tmp[5]  = (x5  + j5)  | 0;
    B[bout++] = tmp[6]  = (x6  + j6)  | 0;
    B[bout++] = tmp[7]  = (x7  + j7)  | 0;
    B[bout++] = tmp[8]  = (x8  + j8)  | 0;
    B[bout++] = tmp[9]  = (x9  + j9)  | 0;
    B[bout++] = tmp[10] = (x10 + j10) | 0;
    B[bout++] = tmp[11] = (x11 + j11) | 0;
    B[bout++] = tmp[12] = (x12 + j12) | 0;
    B[bout++] = tmp[13] = (x13 + j13) | 0;
    B[bout++] = tmp[14] = (x14 + j14) | 0;
    B[bout++] = tmp[15] = (x15 + j15) | 0;
  }

  function blockCopy(dst, di, src, si, len) {
    while (len--) dst[di++] = src[si++];
  }

  function blockXOR(dst, di, src, si, len) {
    while (len--) dst[di++] ^= src[si++];
  }

  function blockMix(tmp, B, bin, bout, r) {
    blockCopy(tmp, 0, B, bin + (2*r-1)*16, 16);
    for (var i = 0; i < 2*r; i += 2) {
      salsaXOR(tmp, B, bin + i*16,      bout + i*8);
      salsaXOR(tmp, B, bin + i*16 + 16, bout + i*8 + r*16);
    }
  }

  function integerify(B, bi, r) {
    return B[bi+(2*r-1)*16];
  }

  function stringToUTF8Bytes(s) {
    var arr = [];
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c < 0x80) {
        arr.push(c);
      } else if (c < 0x800) {
        arr.push(0xc0 | c >> 6);
        arr.push(0x80 | c & 0x3f);
      } else if (c < 0xd800) {
        arr.push(0xe0 | c >> 12);
        arr.push(0x80 | (c >> 6) & 0x3f);
        arr.push(0x80 | c & 0x3f);
      } else {
        if (i >= s.length - 1) {
          throw new Error('invalid string');
        }
        i++; // get one more character
        c = (c & 0x3ff) << 10;
        c |= s.charCodeAt(i) & 0x3ff;
        c += 0x10000;

        arr.push(0xf0 | c >> 18);
        arr.push(0x80 | (c >> 12) & 0x3f);
        arr.push(0x80 | (c >> 6) & 0x3f);
        arr.push(0x80 | c & 0x3f);
      }
    }
    return arr;
  }

  function bytesToHex(p) {
    /** @const */
    var enc = '0123456789abcdef'.split('');

    var len = p.length,
        arr = [],
        i = 0;

    for (; i < len; i++) {
        arr.push(enc[(p[i]>>>4) & 15]);
        arr.push(enc[(p[i]>>>0) & 15]);
    }
    return arr.join('');
  }

  function bytesToBase64(p) {
    /** @const */
    var enc = ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
              '0123456789+/').split('');

    var len = p.length,
        arr = [],
        i = 0,
        a, b, c, t;

    while (i < len) {
      a = i < len ? p[i++] : 0;
      b = i < len ? p[i++] : 0;
      c = i < len ? p[i++] : 0;
      t = (a << 16) + (b << 8) + c;
      arr.push(enc[(t >>> 3 * 6) & 63]);
      arr.push(enc[(t >>> 2 * 6) & 63]);
      arr.push(enc[(t >>> 1 * 6) & 63]);
      arr.push(enc[(t >>> 0 * 6) & 63]);
    }
    if (len % 3 > 0) {
      arr[arr.length-1] = '=';
      if (len % 3 === 1) arr[arr.length-2] = '=';
    }
    return arr.join('');
  }


  // Generate key.

  var MAX_UINT = (-1)>>>0,
      p = 1;

  if (typeof logN === "object") {
    // Called as: scrypt(password, salt, opts, callback)
    if (arguments.length > 4) {
      throw new Error('scrypt: incorrect number of arguments');
    }

    var opts = logN;

    callback = r;
    logN = opts.logN;
    if (typeof logN === 'undefined') {
      if (typeof opts.N !== 'undefined') {
        if (opts.N < 2 || opts.N > MAX_UINT)
          throw new Error('scrypt: N is out of range');

        if ((opts.N & (opts.N - 1)) !== 0)
          throw new Error('scrypt: N is not a power of 2');

        logN = Math.log(opts.N) / Math.LN2;
      } else {
        throw new Error('scrypt: missing N parameter');
      }
    }

    // XXX: If opts.p or opts.dkLen is 0, it will be set to the default value
    // instead of throwing due to incorrect value. To avoid breaking
    // compatibility, this will only be changed in the next major version.
    p = opts.p || 1;
    r = opts.r;
    dkLen = opts.dkLen || 32;
    interruptStep = opts.interruptStep || 0;
    encoding = opts.encoding;
  }

  if (p < 1)
    throw new Error('scrypt: invalid p');

  if (r <= 0)
    throw new Error('scrypt: invalid r');

  if (logN < 1 || logN > 31)
    throw new Error('scrypt: logN must be between 1 and 31');


  var N = (1<<logN)>>>0,
      XY, V, B, tmp;

  if (r*p >= 1<<30 || r > MAX_UINT/128/p || r > MAX_UINT/256 || N > MAX_UINT/128/r)
    throw new Error('scrypt: parameters are too large');

  // Decode strings.
  if (typeof password === 'string')
    password = stringToUTF8Bytes(password);
  if (typeof salt === 'string')
    salt = stringToUTF8Bytes(salt);

  if (typeof Int32Array !== 'undefined') {
    //XXX We can use Uint32Array, but Int32Array is faster in Safari.
    XY = new Int32Array(64*r);
    V = new Int32Array(32*N*r);
    tmp = new Int32Array(16);
  } else {
    XY = [];
    V = [];
    tmp = new Array(16);
  }
  B = PBKDF2_HMAC_SHA256_OneIter(password, salt, p*128*r);

  var xi = 0, yi = 32 * r;

  function smixStart(pos) {
    for (var i = 0; i < 32*r; i++) {
      var j = pos + i*4;
      XY[xi+i] = ((B[j+3] & 0xff)<<24) | ((B[j+2] & 0xff)<<16) |
                 ((B[j+1] & 0xff)<<8)  | ((B[j+0] & 0xff)<<0);
    }
  }

  function smixStep1(start, end) {
    for (var i = start; i < end; i += 2) {
      blockCopy(V, i*(32*r), XY, xi, 32*r);
      blockMix(tmp, XY, xi, yi, r);

      blockCopy(V, (i+1)*(32*r), XY, yi, 32*r);
      blockMix(tmp, XY, yi, xi, r);
    }
  }

  function smixStep2(start, end) {
    for (var i = start; i < end; i += 2) {
      var j = integerify(XY, xi, r) & (N-1);
      blockXOR(XY, xi, V, j*(32*r), 32*r);
      blockMix(tmp, XY, xi, yi, r);

      j = integerify(XY, yi, r) & (N-1);
      blockXOR(XY, yi, V, j*(32*r), 32*r);
      blockMix(tmp, XY, yi, xi, r);
    }
  }

  function smixFinish(pos) {
    for (var i = 0; i < 32*r; i++) {
      var j = XY[xi+i];
      B[pos + i*4 + 0] = (j>>>0)  & 0xff;
      B[pos + i*4 + 1] = (j>>>8)  & 0xff;
      B[pos + i*4 + 2] = (j>>>16) & 0xff;
      B[pos + i*4 + 3] = (j>>>24) & 0xff;
    }
  }

  var nextTick = (typeof setImmediate !== 'undefined') ? setImmediate : setTimeout;

  function interruptedFor(start, end, step, fn, donefn) {
    (function performStep() {
      nextTick(function() {
        fn(start, start + step < end ? start + step : end);
        start += step;
        if (start < end)
          performStep();
        else
          donefn();
        });
    })();
  }

  function getResult(enc) {
      var result = PBKDF2_HMAC_SHA256_OneIter(password, B, dkLen);
      if (enc === 'base64')
        return bytesToBase64(result);
      else if (enc === 'hex')
        return bytesToHex(result);
      else if (enc === 'binary')
        return new Uint8Array(result);
      else
        return result;
  }

  // Blocking variant.
  function calculateSync() {
    for (var i = 0; i < p; i++) {
      smixStart(i*128*r);
      smixStep1(0, N);
      smixStep2(0, N);
      smixFinish(i*128*r);
    }
    callback(getResult(encoding));
  }

  // Async variant.
  function calculateAsync(i) {
      smixStart(i*128*r);
      interruptedFor(0, N, interruptStep*2, smixStep1, function() {
        interruptedFor(0, N, interruptStep*2, smixStep2, function () {
          smixFinish(i*128*r);
          if (i + 1 < p) {
            nextTick(function() { calculateAsync(i + 1); });
          } else {
            callback(getResult(encoding));
          }
        });
      });
  }

  if (typeof interruptStep === 'function') {
    // Called as: scrypt(...,      callback, [encoding])
    //  shifting: scrypt(..., interruptStep,  callback, [encoding])
    encoding = callback;
    callback = interruptStep;
    interruptStep = 1000;
  }

  if (interruptStep <= 0) {
    calculateSync();
  } else {
    calculateAsync(0);
  }
}

if (typeof module !== 'undefined') module.exports = scrypt;

}).call(this,require("timers").setImmediate)
},{"timers":7}],7:[function(require,module,exports){
(function (setImmediate,clearImmediate){
var nextTick = require('process/browser.js').nextTick;
var apply = Function.prototype.apply;
var slice = Array.prototype.slice;
var immediateIds = {};
var nextImmediateId = 0;

// DOM APIs, for completeness

exports.setTimeout = function() {
  return new Timeout(apply.call(setTimeout, window, arguments), clearTimeout);
};
exports.setInterval = function() {
  return new Timeout(apply.call(setInterval, window, arguments), clearInterval);
};
exports.clearTimeout =
exports.clearInterval = function(timeout) { timeout.close(); };

function Timeout(id, clearFn) {
  this._id = id;
  this._clearFn = clearFn;
}
Timeout.prototype.unref = Timeout.prototype.ref = function() {};
Timeout.prototype.close = function() {
  this._clearFn.call(window, this._id);
};

// Does not start the time, just sets up the members needed.
exports.enroll = function(item, msecs) {
  clearTimeout(item._idleTimeoutId);
  item._idleTimeout = msecs;
};

exports.unenroll = function(item) {
  clearTimeout(item._idleTimeoutId);
  item._idleTimeout = -1;
};

exports._unrefActive = exports.active = function(item) {
  clearTimeout(item._idleTimeoutId);

  var msecs = item._idleTimeout;
  if (msecs >= 0) {
    item._idleTimeoutId = setTimeout(function onTimeout() {
      if (item._onTimeout)
        item._onTimeout();
    }, msecs);
  }
};

// That's not how node.js implements it but the exposed api is the same.
exports.setImmediate = typeof setImmediate === "function" ? setImmediate : function(fn) {
  var id = nextImmediateId++;
  var args = arguments.length < 2 ? false : slice.call(arguments, 1);

  immediateIds[id] = true;

  nextTick(function onNextTick() {
    if (immediateIds[id]) {
      // fn.call() is faster so we optimize for the common use-case
      // @see http://jsperf.com/call-apply-segu
      if (args) {
        fn.apply(null, args);
      } else {
        fn.call(null);
      }
      // Prevent ids from leaking
      exports.clearImmediate(id);
    }
  });

  return id;
};

exports.clearImmediate = typeof clearImmediate === "function" ? clearImmediate : function(id) {
  delete immediateIds[id];
};
}).call(this,require("timers").setImmediate,require("timers").clearImmediate)
},{"process/browser.js":5,"timers":7}],8:[function(require,module,exports){
/*!
 * aprico-ui
 * Universal UI implementation for the Aprico Password Manager. 
 * Copyright (c) 2018 Pino Ceniccola | GPLv3
 * https://aprico.org
 */

'use strict';


const VERSION = '0.1.2';

const aprico = require('aprico-gen');

const VERSION_TREE = {
  'aprico-gen' : aprico.version,
  'aprico-ui' : VERSION
}

// Save a few bytes because tiny-sha256 includes... its source code in a var
// const sha256 = require('tiny-sha256');
const sha256 = function a(b){function c(a,b){return a>>>b|a<<32-b}for(var d,e,f=Math.pow,g=f(2,32),h="length",i="",j=[],k=8*b[h],l=a.h=a.h||[],m=a.k=a.k||[],n=m[h],o={},p=2;64>n;p++)if(!o[p]){for(d=0;313>d;d+=p)o[d]=p;l[n]=f(p,.5)*g|0,m[n++]=f(p,1/3)*g|0}for(b+="\x80";b[h]%64-56;)b+="\x00";for(d=0;d<b[h];d++){if(e=b.charCodeAt(d),e>>8)return;j[d>>2]|=e<<(3-d)%4*8}for(j[j[h]]=k/g|0,j[j[h]]=k,e=0;e<j[h];){var q=j.slice(e,e+=16),r=l;for(l=l.slice(0,8),d=0;64>d;d++){var s=q[d-15],t=q[d-2],u=l[0],v=l[4],w=l[7]+(c(v,6)^c(v,11)^c(v,25))+(v&l[5]^~v&l[6])+m[d]+(q[d]=16>d?q[d]:q[d-16]+(c(s,7)^c(s,18)^s>>>3)+q[d-7]+(c(t,17)^c(t,19)^t>>>10)|0),x=(c(u,2)^c(u,13)^c(u,22))+(u&l[1]^u&l[2]^l[1]&l[2]);l=[w+x|0].concat(l),l[4]=l[4]+w|0}for(d=0;8>d;d++)l[d]=l[d]+r[d]|0}for(d=0;8>d;d++)for(e=3;e+1;e--){var y=l[d]>>8*e&255;i+=(16>y?0:"")+y.toString(16)}return i};

const Identicon = require('identicon.js');

const DEFAULT_TEMPLATES = require('./templates.js');

const utils = require('./utils.js');



const isWebExt = (typeof browser !== 'undefined' && browser.runtime && browser.runtime.id) || (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id);

/**
 *  Web Extension API, state of the art.
 *  We're going to use the "chrome" APIs based on callbacks
 *  until this mess is cleared:
 *  https://github.com/mozilla/webextension-polyfill/issues/3
 *  https://developer.microsoft.com/en-us/microsoft-edge/platform/issues/9421085/
 *
 *  Long story short: Microsoft did it wrong again using the new 
 *  standard "browser" namespace but based on the old "chrome" APIs
 *  (using callbacks instead of promises).
 *
 *  Temporary fix: Firefox supports both "browser" (promise based) and
 *  "chrome" (callback based), Edge supports only "browser" but callback
 *  based. So, use "chrome" where available and call things with its
 *  name in Edge. 
 */

if (isWebExt && typeof chrome === "undefined") window.chrome = browser;




const IDENTICON_OPTIONS = {
  foreground: [239, 61, 51, 255],
  background: [255, 255, 255, 255],
  margin: 0.24,
  size: 41,
  format: 'svg'
};


let _root;
let _hashId;
let template;

const hashIdKey = 'hashId_' + VERSION_TREE['aprico-gen'].replace(/\./g , "_");












function setHashId(hashId) {
  _hashId = hashId;
  if (isWebExt) {
    chrome.storage.local.set({'hashId': hashId}, renderMain);
  } else {
    localStorage.setItem('hashId', hashId);
    renderMain();
  }
}

function resetHashId() {
  _hashId = false;
  if (isWebExt) {
    chrome.storage.local.set({'hashId': ''}, renderLogin);
  } else {
    localStorage.setItem('hashId', '');
    renderLogin();
  }
}


function onHashId(result) {
  //console.log(result);
  if (result && result.hashId) {
    _hashId = result.hashId;
    renderMain();
  } else {
    _hashId = false;
    renderLogin();
  }
}












function bootstrap(element, user_template){

  _root = document.querySelector(element);

  if (!_root) throw new Error("Root element is undefined.");

  template = (user_template) ? user_template : DEFAULT_TEMPLATES;

  if (isWebExt) {
    _root.classList.add('aprico-webext');
    chrome.storage.local.get('hashId', onHashId);
  } else {
    _root.classList.add('aprico-browser');
    let hashId = localStorage.getItem('hashId');
    onHashId({ 'hashId' : hashId });
  }

  if (navigator.platform.toUpperCase().indexOf('MAC')>=0) {
    _root.classList.add('aprico-macOS');
  } else {
    _root.classList.add('aprico-otherOS');
  }


}














function renderLogin() {

  let node = utils.stringToDom(template.login);

  if (_root.firstChild) _root.removeChild(_root.firstChild);

  _root.appendChild(node);
  
  setupLogin();
  setupCommon();
}


function renderMain() {

  let node = utils.stringToDom(template.main);

  if (_root.firstChild) _root.removeChild(_root.firstChild);

  _root.appendChild(node);

  setupMain();
  setupCommon();
}



function setupLogin(){

  let $hashId = utils.getId('ap-hashid');
  let $login = utils.getId('ap-trigger-login');
  $hashId.focus();
  $login.addEventListener('click',function(e){
      e.preventDefault();
      if ($hashId.value) {
        _hashId = aprico.getHashId($hashId.value);
        setHashId(_hashId);
      } else {
        $hashId.focus();
      }
  });

};


function setupMain(){

  let $pass         = utils.getId('ap-pass');
  let $service      = utils.getId('ap-service');
  let $result       = utils.getId('ap-result');
  let $trigger      = utils.getId('ap-trigger-gen');

  // extra fields
  let $variant      = utils.getId('ap-variant');
  let $letters      = utils.getId('ap-letters');
  let $numbers      = utils.getId('ap-numbers');
  let $symbols      = utils.getId('ap-symbols');
  let $length       = utils.getId('ap-length');
  
  let $triggerExtra = utils.getId('ap-trigger-extra');
  let $label        = utils.getId('a-pass-label');

  let $triggerCopy  = utils.getId('ap-copy');
  let $triggerShow  = utils.getId('ap-show');

  let $extraDiv     = utils.getId('aprico-extra');
  let $resultDiv    = utils.getId('aprico-result');
  let $aboutDiv     = utils.getId('aprico-about');

  // Autofocus Service or Password inputs
  if (isWebExt) {
    chrome.tabs.query({active:true,currentWindow:true}, function(tabs){
      if (tabs[0].url.indexOf('.') > 0) {
        $service.value = aprico.normalizeService(tabs[0].url);
        $pass.focus();
      } else {
        $service.focus();
      }
    });
  } else {
    $service.focus();
  }
  

  // Normalize Service on blur
  $service.addEventListener('blur',function(e){
    this.value = aprico.normalizeService(this.value);
  });


  // Identicon support
  $pass.addEventListener('input',function(e){
    if (this.value.length) {
      // this.value to base64 because tiny-sha256 works with ASCII only
      let value64 = btoa(encodeURIComponent(this.value).replace(/%([0-9A-F]{2})/g, function(match, p1) {
          return String.fromCharCode(parseInt(p1, 16));
      }));
      let data = new Identicon(sha256(_hashId+value64), IDENTICON_OPTIONS).toString();
      $pass.style.backgroundImage = 'url(data:image/svg+xml;base64,' + data + ')';
    } else {
      $pass.style.backgroundImage = '';
    }
  });


  // Simulate submission
  $pass.addEventListener('keyup',function(e){
     if (e.key === "Enter") generate();
  });


  // Extra
  $triggerExtra.addEventListener('click',function(e){
    e.preventDefault();
    if (this.classList.contains('bg-gray-2')) {
      this.classList.remove('bg-gray-2');
      show($aboutDiv);
    } else {
      this.classList.add('bg-gray-2');
      show($extraDiv);
    }
    
  });


  // Switch Password type
  $result.addEventListener('focus', function(){
    this.type = 'text';
  });
  $result.addEventListener('blur', function(){
    this.type = 'password';
  });



  // Generating Password
  $trigger.addEventListener('click', generate);

  async function generate(e) {
    // 0. Validate fields
    if (!$service.value) {$service.focus();return false;}
    if (!$pass.value) {$pass.focus();return false;}
    
    let timerId,
        results,
        copy;


    // 1. Prepare UI
    let step1 = await new Promise(function(resolve) {

      $label.classList.remove('icon','icon-done','icon-alldone');
      $triggerCopy.classList.add('hidden');
      $triggerShow.classList.add('hidden');
      $result.classList.remove('border-red');

      $triggerExtra.classList.remove('bg-gray-2');

      show($resultDiv);

      //utils.getId('aprico-result').classList.add('bg-black');

      timerId = setInterval(function(){
        $label.textContent += '.';
      },50);

      $label.classList.add('red');
      $label.textContent = 'Generating.';
          
      $trigger.disabled = true;
      $triggerExtra.disabled = true;
      $result.value = '';

      return setTimeout(resolve,100);
    });

    // 2. Generate Password
    let step2 = await new Promise(function(resolve){
      
      let time = new Date().getTime();

      results = aprico.getPassword($pass.value, $service.value, _hashId, {
        length:  +$length.value,
        letters: +$letters.checked,
        numbers: +$numbers.checked,
        symbols: +$symbols.checked,
        variant: $variant.value
      });

      //console.log((new Date().getTime()) - time);

      // in step 2 because... timing
      $result.value = results.pass;
      results = false;
      copy = utils.copyToClipboard($result);

      return setTimeout(resolve,100);
    });

    // 3. Resolve UI
    let step3 = await new Promise(function(resolve){

      $result.classList.add('border-red');

      $label.classList.remove('red');

      clearInterval(timerId);

      if (copy) {
        $label.classList.add('icon','icon-alldone');
        $label.textContent = 'Password copied to clipboard.';
      } else {
        $label.classList.add('icon','icon-done');
        $label.textContent = 'Password is ready.';
        $triggerCopy.classList.remove('hidden');
      }

      $triggerShow.classList.remove('hidden');
      
      $trigger.disabled = false;
      $triggerExtra.disabled = false;

      return resolve();
    });

  
  };



  $triggerCopy.addEventListener('click',function(e){
    let copy = utils.copyToClipboard($result);
    if (copy) $label.textContent = 'Password copied to clipboard.';
  });


  // Reset hashId
  let $reset = utils.getId('ap-delete-hash');
  $reset.addEventListener('click',resetHashId);

  // Show Password
  $triggerShow.addEventListener('click',function(e){
    $result.focus();
  });

  // Switch About/Results
  function show(section){
    $resultDiv.hidden = true;
    $aboutDiv.hidden = true;
    $extraDiv.hidden = true;
    section.hidden = false;
  };

  // hide results on form change
  let formEls = document.querySelectorAll('input');
  Array.from(formEls).forEach(function(el){
    el.addEventListener('input',function(){
      if ($resultDiv.hidden != true) show($aboutDiv);
    });
  });

  // At least one checkbox selected
  let checkboxes = document.querySelectorAll('.switch-toggle');
  Array.from(checkboxes).forEach(checkbox => checkbox.addEventListener('change', checkboxOnChange));
  function checkboxOnChange(){
    let checkedOne = Array.prototype.slice.call(checkboxes).some(x => x.checked);
    if (!checkedOne) this.checked = true;
  };

  // Validate characters count
  $length.addEventListener('blur', function(){
    if (+this.value == 0) this.value = 20;
    else if (+this.value < 4) this.value = 4;
    else if (+this.value > 40) this.value = 40;
  });

}


function setupCommon(){

  // links in new window in web-ext
  if (isWebExt) {
    Array.from(document.querySelectorAll('.webext-newlink')).forEach(
      _link => _link.addEventListener('click', (e) => {
        e.preventDefault();
        window.open(_link.getAttribute('href'));
      })
    );
  }

}

module.exports = bootstrap;
module.exports.version = VERSION_TREE;

},{"./templates.js":10,"./utils.js":11,"aprico-gen":1,"identicon.js":3}],9:[function(require,module,exports){


const apricoUi = require('./aprico-ui.js');

apricoUi('#aprico');
},{"./aprico-ui.js":8}],10:[function(require,module,exports){
/*
 * Aprico UI Templates
*/

const templates = {
	login: `
  <div id="aprico-login" class="p2 sm-p3 bg-white">
	<div class="mb2">
      <label class="label">ID</label>
      <input class="sm-h3" type="text" id="ap-hashid" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">
  	</div>
  	<div class="mb2 h6">
  		<p class="sm-h5"><strong>Please choose an ID:</strong> it can be your e-mail address, your nickname or a longer passphrase.</p>
      <p>It will be only asked once, but please <strong>make sure to remember it</strong> as there is no way to recover your ID.</p>
    </div>
  	<div class="mb2">
      <button id="ap-trigger-login" class="btn btn-primary h6 caps white">Start using Aprico</button>
  	</div>
    <div class="border-top border-gray pt2">
      <p class="h6 m0"><strong>aprico</strong> is a deterministic password manager that works 100% in your browser. No data will ever be sent to any server or cloud. You can read more in our super friendly <a class="webext-newlink" href="https://aprico.org/privacy.html">Privacy Policy</a>.</h6>
    </div>
    </div>
  	`,
	main: `
  <div id="aprico-main" class="flex flex-column col-12">
  <div class="p2 sm-p3 bg-white">
  	<div class="mb2">
      <label class="label">Service</label>
      <input class="sm-h3 sm-mb2" type="text" placeholder="website.com or appname" id="ap-service" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">
  	</div>
  	<div class="mb2">
      <form onsubmit="return false;">
      <input id="fake-user-text-field" type="hidden" autocomplete="username" value="aprico master password">
      <label class="label">Master Password</label>
      <input id="ap-pass" class="sm-h3 sm-mb2 bg-identicon" type="password" autocomplete="password">
      </form>
  	</div>
  	<div class="sm-mb2">
    	<div class="flex">
      	<button id="ap-trigger-gen" class="btn btn-primary white h6 caps" style="margin-left:1px">Get Password</button>
      	<span class="flex-auto"></span>
      	<button id="ap-trigger-extra" class="btn h6 caps right icon icon-opts px0 border-gray rounded"><span style="opacity:0">More</span></button>
    	</div>
  	</div>
  </div>

  <div class="flex-auto flex flex-column bg-gray-1 border-top border-gray-2" style="min-height:200px">

  <div id="aprico-extra" class="p2 sm-p3" hidden>
    <div class="flex justify-between mb2">
        <div class="sm-mb2 col-3 ">
            <label class="label">Length</label>
            <input class="lg-h3" type="number" min="4" max="40" value="20" id="ap-length">
        </div>
        <div class="sm-mb2 col-9 flex-auto pl2 sm-pl4 md-pl2 lg-pl4">
            <label class="label">Alphabet</label>
            <ul class="list-reset flex justify-between center">
                <li>
                    <input type="checkbox" checked id="ap-letters" class="switch-toggle switch-toggle-round">
                    <label for="ap-letters"><span class="mt2 block">Letters</span></label>
                </li>
                <li>
                    <input type="checkbox" checked id="ap-numbers" class="switch-toggle switch-toggle-round">
                    <label for="ap-numbers"><span class="mt2 block">Numbers</span></label>
                </li>
                <li>
                    <input type="checkbox" checked id="ap-symbols" class="switch-toggle switch-toggle-round">
                    <label for="ap-symbols"><span class="mt2 block">Symbols</span></label>
                </li>
            </ul>
        </div>
    </div>
    <div class="">
        <div class="-mb2">
            <label class="label">Variant</label>
            <input class="sm-h3" type="text" id="ap-variant">
        </div>
    </div>
  </div>

  <div id="aprico-result" class="p2 sm-p3" hidden>
  <div class="mb2">
      <label class="label bold mb2" id="a-pass-label">Password</label>
      <input class="sm-h3 sm-mb2 monospace" type="password" id="ap-result" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false" readonly="true">
  </div>
  <div class="flex">
  <button class="btn btn-small h6 px0 hidden mr2 icon icon-view weight-400" id="ap-show">Show</button>
  <button class="btn btn-small h6 px0 hidden icon icon-copy weight-400" id="ap-copy">Copy</button>
  </div>
  </div>

  <div id="aprico-about" class="flex-auto flex flex-column col-12">
  <!-- <div class="flex flex-column bg-gray-1"> -->
  <div class="p2 sm-p3">
    <p class="h5">Thank you for using <strong>aprico</strong>.</p>
    <div class="webext-notice h6">
      <p class="m0"><strong>Tip:</strong> Easily access aprico with 
      <code><span class="macOS-inline-notice">cmd</span><span class="otherOS-inline-notice">ctrl</span></code> + <code>space</code>.</p>
    </div>
  </div>
  <span class="flex-auto"></span>
  <div class="flex p2 sm-p3">
  <a class="btn btn-small h6 px0 icon icon-open weight-400 webext-newlink" href="https://aprico.org">About</a>
  <a class="btn btn-small h6 px0 icon icon-open weight-400  ml2 webext-newlink" href="mailto:pino@aprico.org?subject=Feedback%20about%20aprico">Feedback</a>

  <button id="ap-link-online" class="hide btn btn-small h6 px0 icon icon-open">Online Version</button>
  <span class="flex-auto"></span>
  <button class="btn btn-small h6 px0 icon icon-logout" id="ap-delete-hash">Change ID</button>
  </div>  
  <!-- </div> -->
  </div>

  </div>
</div>
	`
}

module.exports = templates;
},{}],11:[function(require,module,exports){

'use strict';


const utils = {};

utils.getId = function(id){
    return document.getElementById(id);
}

utils.stringToDom = function(string){
    return document.createRange().createContextualFragment(string.trim());
}

/**
 * Copy to clipboard, state of the art.
 * 
 * For Web Extensions: Always require permission (clipboardWrite).
 *
 * For Browsers:
 * - Chrome + Safari (check quirks) allow async copy, this let
 *   us change the UI without freezing the browser.
 *    
 * - Firefox + Edge don't allow async copy, only solution to date
 *   is to degrade gracefully to click-to-copy only (no autocopy
 *   after generation).
 *
 * Reference:
 * https://developer.microsoft.com/en-us/microsoft-edge/platform/issues/7728456/
 * http://hansifer.com/clipboardCopyTest.html
 * https://bugzilla.mozilla.org/show_bug.cgi?id=1012662#c51
 */
utils.copyToClipboard = function(element) {
 
  element.type = 'text';

  // copy to clipboard
  element.select();

  // TO DO: ios quirks...
  // ref: https://stackoverflow.com/questions/34045777/copy-to-clipboard-using-javascript-in-ios
/*
            let range = document.createRange();
            range.selectNodeContents(element);
            let selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);
            element.setSelectionRange(0, 999999);  
*/
  let success = document.execCommand("copy");

 	//console.log('copy', success);

	element.type = 'password';

  // deselect
  //var activeEl = document.activeElement;
  //if ('selectionStart' in activeEl) {
  //  element.selectionEnd = activeEl.selectionStart;
  //}

  //if ('selectionStart' in activeEl) {
    element.selectionEnd = element.selectionStart;
  //}
  
  //selection.removeAllRanges();

 	element.blur();

	return success;
}





utils.chainOnTransitionEnd = function( callback, _this ) {

	let runOnce = function(e){
		e.target.removeEventListener( e.type, runOnce );
		if (e.target == _this) callback();
	}

	_this.addEventListener( 'transitionend', runOnce );
	// if no transition
	// if ( getComputedStyle( this )[ 'transition-duration' ] == '0s' ) callback();
	return this;
};


module.exports = utils;
},{}]},{},[9]);
