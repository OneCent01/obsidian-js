# Obsidian-JS
## *Fortify your Node server with rock hard authentication*

A light NodeJS library of pure functions useful for secure server-side authetnication. Password hashing, token generation, and response header setting. 

<img style="float:right;" src="https://gamepedia.cursecdn.com/minecraft_gamepedia/2/23/Obsidian.png"/>


Provides a set of easy-to-use tools that allows for rapid development of secure servers. It relies on argon2 for password hashing/verification and jsonwebtoken for token generation/authentication. 


Obsidian's full potential is realized when used in conjunction with an web API framework, such as ExpressJS. [A basic extensible server with secure user adding and authenticating can be accomplished with these two libraries in about 60 lines of code!](https://gist.github.com/OneCent01/fa52829c9770472d16a5af20b6f75a16)

## Installing

In a terminal, navigate to the root of the application to add the library, and run:

`$ npm install --save obsidian-js`

The obsidian module can now be made available in the node files using `require`:

```
const obsidian = require('obsidian-js')

// all available utilities: 
const {
	secureRandom,
	secureSalt,
	hash,
	verifyHash,
	issueToken,
	verifyToken,
	verifyReqToken,
	validFrameOptSetting,
	validXssProtectionSetting,
	obsidianWare,
	verifyReqTokenWare,
	frameOptionsWare,
	xssProtectionWare,
	contentTypeWare
} = obsidian
```


## Docs


**secureRandom(length, type)**

async function securely generating random sequences using Node's crypto module

	-length: integer, how long the returned sequence should be

	-type: stirng, supports hex strings ('hex') and integers ('int')

	-> returns a promise resolved with the random sequence or rejecting with a `false` boolean and an error


**secureSalt(length, type)**

async function securely generating random a salt of given length and type using Node's crypto module

	-length: integer, how long the returned salt should be

	-type: string, the type of salt desired, currently only supports 'hex' and 'int' types

	-> returns a promise resolved with the random sequence or rejecting with a `false` boolean


**hash(saltedPass)**

async hashing function using the argon2 algorithm

	-saltedPass: string, the user's password concatenated with a salt

	-> returns a promise resolved with a hashed string


	Only call this function when setting a password.

	Saving plaintext passwords is VERY BAD!!


	To avoid saving user passwords, save the salt and returned 
	hash in association with the user. These will be used later 
	for identity verification without exposing the original 
	password.


**verifyHash(saltedPass, hash)**

async function verifying the given salted password is the same as the one used to originally generate the given hash

	-saltedPass: string, the user's entered password concatenated with a salt

	-hash: string, argon2 hash saved in association with the user

	-> returns a promise resolved with a boolean


	When a login request is made, the server needs to ensure 
	the person requesting the resource is who they say they 
	are. Fetch the user's login info from yourdatabase, which 
	should include a hash and salt. 

	DO NOT try and re-hash the salted password and compare it 
	to the previous hash, that won't work. There's a degree of 
	random in the hashing algorithm, meaning the same password 
	won't hash into the same thing twice. 

	argon2's verify takes this into account and can ensure the given password was 
	used to generate the hash using magic. 


**issueToken(data, opts)**

synchronously generates and returns a JSON web token
	-data: ANY, identifying information required for user permissions
				-> the payload can be stringifiable value or data structure


	-opts: object, contains the secret key and signing options

	-> returns a json web token string


	This token should be kept in memory, sent in on every
	seubsequent request on the `Authorization` header.

```
// example call: 
const userToken = issueToken({/*USERDATA*/}, {
	secretKey: 'GlowInTheDarkDemons',
	signOpts: {expiresIn: (24 * 60)}
})

// store locally using localStorage browser API
localStorage.setItem('token', userToken)

// sending in the token:
const fetch = (method, url, payload=undefined) => new Promise((resolve, reject) => {
	const request = new XMLHttpRequest()

	// ...

	const token = localStorage.getItem('token')
	if(token) {
		request.withCredentials = true
		request.setRequestHeader('Authorization', token)
	}
	request.send(payload)
})

```


**verifyToken(token, opts)**

synchronously ensures the token is valid, has not expired, and has not been tampered with

	-token: json web token returned from issueToken

	-opts: object, can contain two sub objects to overwrite defaults. MUST match the parameters used when generating the hash for verification to succeed. 

	-> returns an object with a `success` property indicating the token's validity, and either an `error` string or a `user` prop with the token's decoded payload 


```
// example call: 
verifyToken(<TOKEN>, {
	headerOpts: {alg: 'RS256'},
	tokenOpts: {
		expiresIn: (24 * 60),
		secretKey: 'GlowInTheDarkDemons'
	}
})
```

**verifyReqTokenWare(opts)**

Middleware returning function for Express.JS check the token sent in with the request. If it's invalid, expired, or been tampered with, immediately reject the request. Otherwise, the user is valid. Allow the request to continue  falling through the Express functions. 
	
	-opts: object, _should_ contain an array of strings at `unrestrictedPaths`. Optional props:
		*verify: function, must return an object with a success property. uses `obsidian.verifyToken` by default
		*verifyOpts: object, passed to the verfy function as the second argument after the token string
		*disableSecurity: boolean, prevent security measures from being applied to the response. False by default
		*frameOpts: object, used when securirty is enabled to change default X-Frame-Options header setting to something other than 'SAMEORIGIN' (must be 'DENY' or 'ALLOW-ORIGIN' with a domain)

	-> returns a function that accepts three arguments (req, res, next) which ensures the token attached to the request's Authorization header is valid


```
// example usage:

const unrestrictedPaths = ['/auth-user', '/add-user']
const verificationMiddleware = verifyReqTokenWare({ unrestrictedPaths })

// every request will be passed through this endpoint,
// to check the senders credentials (token) and possibly  
// terminate the endpoint fallthrough
app.use(verificationMiddleware)
```

**validFrameOptSetting(opts)**

Synchronous function returning a string that's a valid X-Frame-Options header setting. The purpose of this is to prevent any enexpected iFrames from loading. iFrames are particularly useful in clickjacking, an attack vector where the user's action triggers the event listener on the invisible iFrame. 

	-opts: object, optional parameters for the setting
		*setting: string, must be 'DENY', 'SAMEORIGIN', or 'ALLOW-FROM'. If 'ALLOW-FROM', opts MUST also contain domain,
		*donain: required when setting frame option to 'ALLOW-FROM'. Ignored in all other cases, setting changed to 'SAMEORIGIN' from 'ALLOW-FROM' if a domain string is not passed in. 

	-> returns a string that's a valid X-Frame-Options header setting 

**frameOptionsWare(opts)**

Middleware returning function that will set the X-Frame-Options in the header to the given option. If no option is supplied, or the option supplied is invalid, the option 'SAMEORIGIN' will be defaulted to. 

	-opts: object, optional settings:
		*setting: string, must be 'DENY', 'SAMEORIGIN', or 'ALLOW-FROM'. If 'ALLOW-FROM', opts MUST also contain domain,
		*donain: required when setting frame option to 'ALLOW-FROM'. Ignored in all other cases, setting changed to 'SAMEORIGIN' fron 'ALLOW-FROM' if a string is not passed in. 

	-> returns a function that accepts three arguments (req, res, next) which sets the X-Frame-Options header to 'SAMEORIGIN' by default, or will set it to the option specified in the header opt argument. 

```
// example usage: 

const setFrame = frameOptionsWare({setting: 'DENY'})
app.use(setFrame)

```

**obsidianWare(opts)**

Middleware returning function validating tokens and set security headers on the response. Three headers are set by default X-Frame-Options, X-XSS-Protection, and X-Content-Type-Options; by default they are set to `SAMEORIGIN`, `1; mode=block`, and `nosniff`, respectively. These can be turned off or customized to values required to work with your system with the options passed in.

	-opts: object, optional settings:
		*unrestrictedPaths: array of strings, paths to ignore tokens on. i.e. ['/add-user', '/auth-user']
		*verify: function, must return an object with a success property. uses `obsidian.verifyToken` by default
		*verifyOpts: object, passed to the verfy function as the second argument after the token string. Matches the options used when generating the token. 
		*disableFrameSecurity: boolean, setting this to true prevents X-Frame-Options from being set
		*frameOpts: object, can contain a setting, must contain a domain if setting is 'ALLOW-FROM'
		*disableXssProtectionSecurity: boolean, X-XSS-Protection will not be set if this is passed in as true
		*xssProtectionOpts: object, setting (1 || 0), mode (mode || report), and report (URL string)
		*disableContentTypeSecurity: boolean, X-Content-Type-Options header will be set to `nosniff` unless this is passed in as true

	-> returns a middleware function performing token validation on the request and applying security measures to the response 


```
// example usage:

const obsidianGate = obsidianWare({
	unrestrictedPaths: ['/', '/add-user'],
	frameOpts: {
		setting: 'ALLOW-FROM',
		domain: 'https://yahoo.com'
	},
	verifyOpts: {
		headerOpts: {alg: 'RS256'},
		tokenOpts: {
			expiresIn: (24 * 60),
			secretKey: 'GlowInTheDarkDemons'
		}
	}
})

app.use(obsidianGate)
```


**verifyReqToken(token, opts, verify)**

Sychronous function checking whether given token is valid and decode it's payload. 

	-token: token string
	-opts: object, options to pass into verify token function
	-verify: 


**validXssProtectionSetting(opts)**

Sychronous function returning a string which can be validly set on the X-XSS-Protection header. By default set to `1; mode=block`, the most secure setting.

	-opts: object, optional settings
		*setting: 1 or 0,
		*mode: 'mode' or 'report'
		*report: only used if mode is set to report. If mode is report and report is a non-empty string, the setting will be "1; report=REPORT_STRING"

```
// example usage: 

const xssProtectionSetting = validXssProtectionSetting({
	setting: 1, 
	mode: 'report', 
	report: 'https://reporting-uri'
})

app.use((req, res, next) => {
	res.setHeader('X-XSS-Protection', xssProtectionSetting)
	next()
})

```

**xssProtectionWare(opts)**

Middleware returning function setting the X-XSS-Protection header to a valid string. Opts passed to `validXssProtectionSetting` to generate the setting. 

	-opts: object, optional settings
		*setting: 1 or 0,
		*mode: 'mode' or 'report'
		*report: only used if mode is set to report. If mode is report and report is a non-empty string, the setting will be "1; report=REPORT_STRING"


**contentTypeWare()**

Middleware returning function setting the X-Content-Type-Options header in the response to `nosniff`. 

```
// example usage: 

const secureContentTypeHeader = contentTypeWare()

app.use(secureContentTypeHeader)

```